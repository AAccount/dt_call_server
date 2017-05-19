#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/time.h> 
#include <sys/select.h>
#include <netinet/in.h>
#include <signal.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "const.h"
#include "server.hpp"
#include "Utils.hpp"
#include "server_init.hpp"

#include <cmath>
#include <string>
#include <unordered_map> //hash table
#include <vector>
#include <fstream>
#include <random>
#include <algorithm>

#include "Log.hpp"
#include "UserUtils.hpp"

using namespace std;

//information on what each socket descriptor is (command, media) and what it's supposed to be doing if it's a media socket
unordered_map<int, state> sdinfo;

//associates socket descriptors to their ssl structs
unordered_map<int, SSL*>clientssl;

//list of who is a live call with whom
unordered_map<string, string> liveList;

//fail counts of each socket descriptor. if there are too many fails then remove the socket.
//most likely to be used by media sockets during calls. media socket gets reset after a call anyways
//so any fails are going to come from the current call
unordered_map<int, int> failCount;

UserUtils *userUtils = UserUtils::getInstance();

vector<int> removals; //fds the main thread should remove
struct timeval writeTimeout;
unordered_map<string, pthread_t*> pthreads; //map of user --> pthread (2/call because 2 people/call)
pthread_mutex_t removalsMutex = PTHREAD_MUTEX_INITIALIZER;

//setup random number generator for the log relation key (a random number that related logs can use)
random_device rd;
mt19937 mt(rd());
uniform_int_distribution<uint64_t> dist (0, (uint64_t)9223372036854775807);

int main(int argc, char *argv[])
{
	uint64_t initkey = dist(mt);
	string start = (string)"starting call operator V" +(string)VERSION;
	userUtils->insertLog(Log(TAG_INIT, start, SELF, SYSTEMLOG, SELFIP, initkey));

	int cmdFD, cmdPort = DEFAULTCMD; //command port stuff
	int mediaFD, mediaPort = DEFAULTMEDIA; //media port stuff

	string publicKeyFile;
	string privateKeyFile;
	string ciphers = DEFAULTCIPHERS;
	string dhfile = "";

	//use a helper function to read the config file
	readServerConfig(&cmdPort, &mediaPort, &publicKeyFile, &privateKeyFile, &ciphers, &dhfile, userUtils, initkey);

	//helper to setup the ssl context
	SSL_CTX *sslcontext = setupOpenSSL(ciphers, privateKeyFile, publicKeyFile, dhfile, userUtils, initkey);
	if(sslcontext == NULL)
	{
		userUtils->insertLog(Log(TAG_INIT, "could not establish ssl context", SELF, SYSTEMLOG, SELFIP, initkey));
		exit(1);
	}

	//socket read timeout option
	struct timeval readTimeout;
	readTimeout.tv_sec = 0;
	readTimeout.tv_usec = READTIMEOUT;
	//write select timeout
	writeTimeout.tv_sec = 0;
	writeTimeout.tv_usec = WSELECTTIMEOUT;

	//helper to setup the sockets
	struct sockaddr_in serv_cmd, serv_media;
	setupListeningSocket(&readTimeout, &cmdFD, &serv_cmd, cmdPort, userUtils, initkey);
	setupListeningSocket(&readTimeout, &mediaFD, &serv_media, mediaPort, userUtils, initkey);

	//sigpipe is thrown for closing the broken connection. it's gonna happen for a voip server handling mobile clients
	//what're you gonna do about it... IGNORE IT!!
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while(true) //forever
	{
#ifdef VERBOSE
		cout << "------------------------------------------\n----------------------------------------\n";
#endif
		fd_set readfds, writefds;
		FD_ZERO(&readfds);
		FD_SET(cmdFD, &readfds);
		FD_SET(mediaFD, &readfds);
		FD_ZERO(&writefds);
		int maxsd = (cmdFD > mediaFD) ? cmdFD : mediaFD;

		//build the fd watch list consisting of command, and NON live media fds
		for(auto it = clientssl.begin(); it != clientssl.end(); ++it)
		{
			int sd = it->first;
			if(sdinfo[sd] != SOCKMEDIALIVE)
			{//live media fds should be handled in their respective threads
				FD_SET(sd, &readfds);
				FD_SET(sd, &writefds);
				maxsd = (sd > maxsd) ? sd : maxsd;
			}
		}

		//wait for somebody to send something to the server
		int sockets = select(maxsd+1, &readfds, NULL, NULL, NULL);
		if(sockets < 0)
		{
			string error = "read fds select system call error";
			userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
			perror(error.c_str());
			exit(1); //see call thread fx for why
		}
#ifdef VERBOSE
		cout << "select has " << sockets << " sockets ready for reading\n";
#endif
		//now that someone has sent something, check all the sockets to see which ones are writable
		//give a 0.1ms time to check. don't want the request to involve an unwritable socket and
		//stall the whole server
		sockets = select(maxsd+1, NULL, &writefds, NULL, &writeTimeout);
		if(sockets < 0)
		{
			string error = "write fds select system call error";
			userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
			perror(error.c_str());
			exit(1);
		}
#ifdef VERBOSE
		cout << "select has " << sockets << " sockets ready for writing\n";
#endif
		//****************************************************************
		//IMPORTANT: factoring out command and media socket accepting code
		//           tends to produce weird unpredictable side effects.
		//****************************************************************
		//check for a new incoming connection on command port
		if(FD_ISSET(cmdFD, &readfds))
		{
			uint64_t relatedKey = dist(mt);
			struct sockaddr_in cli_addr;
			socklen_t clilen = sizeof(cli_addr);

			int incomingCmd = accept(cmdFD, (struct sockaddr *) &cli_addr, &clilen);
			if(incomingCmd < 0)
			{
				string error = "accept system call error";
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, DONTKNOW, relatedKey));
				perror(error.c_str());
				continue;
			}
			string ip = inet_ntoa(cli_addr.sin_addr);

			//if this socket has problems in the future, give it 1sec to get its act together or giveup on that operation
			if(setsockopt(incomingCmd, SOL_SOCKET, SO_RCVTIMEO, (char*) &readTimeout, sizeof(readTimeout)) < 0)
			{
				string error = "cannot set timeout for incoming media socket from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip, relatedKey));
				perror(error.c_str());
				shutdown(incomingCmd, 2);
				close(incomingCmd);
				continue;
			}

			//setup ssl connection
			SSL *connssl = SSL_new(sslcontext);
			SSL_set_fd(connssl, incomingCmd);

			//in case something happened before the incoming connection can be made ssl.
			if(SSL_accept(connssl) <= 0)
			{
				string error = "Problem initializing new command tls connection from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip, relatedKey));
				SSL_shutdown(connssl);
				SSL_free(connssl);
				shutdown(incomingCmd, 2);
				close(incomingCmd);
			}
			else
			{
				//add the new socket descriptor to the client self balancing tree
				string message = "new command socket from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGCMD, message, SELF, INBOUNDLOG, ip, relatedKey));
				clientssl[incomingCmd] = connssl;
				sdinfo[incomingCmd] = SOCKCMD;
				failCount[incomingCmd] = 0;
			}
		}

		//check for a new incoming connection on media port
		if(FD_ISSET(mediaFD, &readfds))
		{
			uint64_t relatedKey = dist(mt);
			struct sockaddr_in cli_addr;
			socklen_t clilen = sizeof(cli_addr);

			int incomingMedia = accept(mediaFD, (struct sockaddr *) &cli_addr, &clilen);
			if(incomingMedia < 0)
			{
				string error = "accept system call error";
				userUtils->insertLog(Log(TAG_INCOMINGMEDIA, error, SELF, ERRORLOG, DONTKNOW, relatedKey));
				perror(error.c_str());
				continue;
			}
			string ip = inet_ntoa(cli_addr.sin_addr);

			//if this socket has problems in the future, give it 1sec to get its act together or giveup on that operation
			if(setsockopt(incomingMedia, SOL_SOCKET, SO_RCVTIMEO, (char*) &readTimeout, sizeof(readTimeout)) < 0)
			{
				string error = "cannot set timeout for incoming media socket from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGMEDIA, error, SELF, ERRORLOG, ip, relatedKey));
				perror(error.c_str());
				shutdown(incomingMedia, 2);
				close(incomingMedia);
				continue;
			}

			SSL *connssl = SSL_new(sslcontext);
			SSL_set_fd(connssl, incomingMedia);

			//in case something happened before the incoming connection can be made ssl
			if(SSL_accept(connssl) <= 0)
			{
				string error = "Problem initializing new command tls connection from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGMEDIA, error, SELF, ERRORLOG, ip, relatedKey));
				SSL_shutdown(connssl);
				SSL_free(connssl);
				shutdown(incomingMedia, 2);
				close(incomingMedia);
			}
			else
			{
				string message = "new media socket from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGMEDIA, message, SELF, INBOUNDLOG, ip, relatedKey));
				clientssl[incomingMedia] = connssl;
				sdinfo[incomingMedia] = SOCKMEDIANEW;
				failCount[incomingMedia] = 0;
			}
		}


		//check for data on an existing connection
		for(auto it = clientssl.begin(); it != clientssl.end(); ++it)
		{//figure out if it's a command, or voice data. handle appropriately

			//get the socket descriptor and associated ssl struct from the iterator round
			int sd = it->first;
			SSL *sdssl = it->second;
			if(FD_ISSET(sd, &readfds) && sdinfo[sd] != SOCKMEDIALIVE)
			{
#ifdef VERBOSE
				cout << "socket descriptor: " << sd << " was marked as set\n";
#endif
				uint64_t iterationKey = dist(mt);

				//read the socket and make sure it wasn't just a socket death notice
				char inputBuffer[BUFFERSIZE+1];
				int amountRead = readSSL(sdssl, inputBuffer, iterationKey);
				if(amountRead == 0)
				{
					pthread_mutex_lock(&removalsMutex);
					removals.push_back(sd);
					pthread_mutex_unlock(&removalsMutex);
					continue;
				}

				state sdstate = sdinfo[sd];
				if(sdstate == SOCKCMD)
				{
					//what was previously a workaround now has an official purpose: heartbeat/ping ignore byte
					//this byte is just sent to keep the socket and its various nat tables it takes to get here alive
					string bufferString(inputBuffer);
					if(bufferString == JBYTE)
					{
#ifdef VERBOSE
						cout << "Got a " << JBYTE << " cap for media sd " << sd << "\n";
#endif
						continue;
					}
					string originalBufferCmd = string(inputBuffer); //save original command string before it gets mutilated by strtok
					vector<string> commandContents = parse(inputBuffer);
					string ip = ipFromSd(sd);
					time_t now = time(NULL);

					try
					{
						string command = commandContents.at(1);
						uint64_t timestamp = (uint64_t)stoull(commandContents.at(0)); //catch is for this
						uint64_t maxError = 60*MARGIN_OF_ERROR;
						uint64_t timeDifference = max((uint64_t)now, timestamp) - min((uint64_t)now, timestamp);
						if(timeDifference > maxError)
						{
							//only bother processing the command if the timestamp was valid

							//prepare the error log
							uint64_t mins = timeDifference/60;
							uint64_t seconds = timeDifference - mins*60;
							string error = "command received was outside the "+to_string(MARGIN_OF_ERROR)+" minute margin of error: " + to_string(mins)+"mins, "+to_string(seconds) + "seconds";
							error = error + " (" + originalBufferCmd + ")";
							string user = userUtils->userFromFd(sd, COMMAND);
							userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

							//send the rejection to the client
							string invalid = to_string(now) + "|resp|invalid|command\n";
							write2Client(invalid, sdssl, iterationKey);
							continue;
						}
						if(command == "login1") //you can do string comparison like this in c++
						{//timestamp|login1|username
							string username = commandContents.at(2);
							string ip = ipFromSd(sd);
							userUtils->insertLog(Log(TAG_LOGIN, originalBufferCmd, username, INBOUNDLOG, ip, iterationKey));

							//don't immediately remove old command and media fd. this would allow anyone
							//	to send a login1 command and kick out a legitimately logged in person.

							//get the user's public key
							RSA *publicKey = userUtils->getUserPublicKey(username);
							if(publicKey == NULL)
							{
								//not a real user. send login rejection
								string invalid = to_string(now) + "|resp|invalid|command";
								userUtils->insertLog(Log(TAG_LOGIN, invalid, username, OUTBOUNDLOG, ip, iterationKey));
								write2Client(invalid, sdssl, iterationKey);
								pthread_mutex_lock(&removalsMutex);
								removals.push_back(sd); //nothing useful can come from this socket
								pthread_mutex_unlock(&removalsMutex);
								continue;
							}

							//generate the challenge gibberish
							string challenge = Utils::randomString(CHALLENGE_LENGTH);
#ifdef VERBOSE
							cout << "challenge: " << challenge << "\n";
#endif
							userUtils->setUserChallenge(username, challenge);
							unsigned char* enc = (unsigned char*)malloc(RSA_size(publicKey));
							int encLength = RSA_public_encrypt(challenge.length(), (const unsigned char*)challenge.c_str(), enc, publicKey, RSA_PKCS1_PADDING);
							string encString = stringify(enc, encLength);
							free(enc);

							//send the challenge
							string resp = to_string(now) + "|resp|login1|" + encString;
							write2Client(resp, sdssl, iterationKey);
							userUtils->insertLog(Log(TAG_LOGIN, resp, username, OUTBOUNDLOG, ip, iterationKey));
#ifdef VERBOSE
							cout << "challenge gibberish: " << challenge << "\n";
#endif
							continue; //login command, no session key to verify, continue to the next fd after proccessing login1
						}
						else if(command == "login2")
						{//timestamp|login2|username|challenge

							//ok to store challenge answer in the log. challenge is single use, disposable
							string username = commandContents.at(2);
							string ip = ipFromSd(sd);
							userUtils->insertLog(Log(TAG_LOGIN, originalBufferCmd, username, INBOUNDLOG, ip, iterationKey));
							string triedChallenge = commandContents.at(3);

							//check the challenge
							//	an obvious loophole: send "" as the challenge since that's the default value
							//	DON'T accept the default ""
							string answer = userUtils->getUserChallenge(username);
#ifdef VERBOSE
							cout << "@username: " << username << " answer: " << answer << " attempt: " << triedChallenge << "\n";
#endif
							if (answer == "" || triedChallenge != answer) //no challenge registered for this person or wrong answer
							{
								//person doesn't have a challenge to answer or isn't supposed to be
								string invalid = to_string(now) + "|resp|invalid|command";
								userUtils->insertLog(Log(TAG_LOGIN, invalid, username, OUTBOUNDLOG, ip, iterationKey));
								write2Client(invalid, sdssl, iterationKey);
								pthread_mutex_lock(&removalsMutex);
								removals.push_back(sd); //nothing useful can come from this socket
								pthread_mutex_unlock(&removalsMutex);

								//reset challenge in case it was wrong
								userUtils->setUserChallenge(username, "");
								continue;
							}

							//now that the person has successfully logged in, remove the old information.
							//	this person has established new connections so it's 100% sure the old ones aren't
							//	needed anymore.
							int oldcmd = userUtils->userFd(username, COMMAND);
							if(oldcmd > 0)
							{//remove old SSL structs to prevent memory leak
#ifdef VERBOSE
								cout << "previous command socket/SSL* exists, will remove\n";
#endif
								pthread_mutex_lock(&removalsMutex);
								removals.push_back(oldcmd);
								pthread_mutex_unlock(&removalsMutex);
								//dissociate old fd from user otherwise the person will have 2 commandfds listed in
								//	comamandfdMap. however the User object pointed to in commandfd map will have the
								//	new fd. clear session will clear all the new login information at the end of this
								//	select round. don't wait until then. do it now.
								userUtils->clearSession(username);
							}

							int oldmedia = userUtils->userFd(username, MEDIA);
							if(oldmedia > 0)
							{//remove old SSL structs to prevent memory leak
#ifdef VERBOSE
								cout << "previous meida socket/SSL* exists, will remove\n";
#endif
								pthread_mutex_lock(&removalsMutex);
								removals.push_back(oldmedia);
								pthread_mutex_unlock(&removalsMutex);
								userUtils->clearSession(username);
							}

							//challenge was correct and wasn't "", set the info
							string sessionkey = Utils::randomString(SESSION_KEY_LENGTH);
							userUtils->setUserSession(username, sessionkey);
							userUtils->setFd(sessionkey, sd, COMMAND);
							userUtils->setUserChallenge(username, ""); //reset after successful completion

							//send an ok
							string resp = to_string(now) + "|resp|login2|" + sessionkey;
							write2Client(resp, sdssl, iterationKey);
#ifndef VERBOSE
							resp = to_string(now) + "|resp|login2|" + SESSION_KEY_PLACEHOLDER;
#endif
							userUtils->insertLog(Log(TAG_LOGIN, resp, username, OUTBOUNDLOG, ip, iterationKey));
							continue; //login command, no session key to verify, continue to the next fd after proccessing login2
						}

						//done processing login commands.
						//all (non login) commands have the format timestamp|COMMAND|PERSON_OF_INTEREST|sessionkey
						string sessionkey = commandContents.at(3);
						string user = userUtils->userFromFd(sd, COMMAND);
#ifndef VERBOSE //unless needed, don't log session keys as they're still in use
						originalBufferCmd = commandContents.at(0) + "|" + commandContents.at(1) + "|" + commandContents.at(2) + "|" + SESSION_KEY_PLACEHOLDER;
#endif
						if(!userUtils->verifySessionKey(sessionkey, sd))
						{
							string error = "INVALID SESSION ID. refusing command ("+originalBufferCmd+")";
							userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

							string invalid = to_string(now) + "|resp|invalid|command";
							write2Client(invalid, sdssl, iterationKey);
							userUtils->insertLog(Log(TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip, iterationKey));
							continue;
						}

						//variables written from touma calling zapper perspective
						//command will come from touma's cmd fd
						if (command == "call")
						{//timestamp|call|zapper|toumakey

							string zapper = commandContents.at(2);
							string touma = user;
							userUtils->insertLog(Log(TAG_CALL, originalBufferCmd, touma, INBOUNDLOG, ip, iterationKey));

							//double check touma has a mediafd
							int toumaMediaFd = userUtils->userFd(touma, MEDIA);
							if(toumaMediaFd == 0)
							{
								string invalid = to_string(now) + "|resp|invalid|command";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_CALL, invalid, touma, OUTBOUNDLOG, ip, iterationKey));
								continue;
							}

							//find out if zapper has both a command and media fd
							int zapperMediaFd = userUtils->userFd(zapper, MEDIA);
							int zapperCmdFd = userUtils->userFd(zapper, COMMAND);
							if(zapperMediaFd == 0 || zapperCmdFd == 0 )
							{
								string na = to_string(now) + "|ring|notavailable|" + zapper;
								write2Client(na, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_CALL, na, touma, OUTBOUNDLOG, ip, iterationKey));
								continue; //while not really an invalid command, there's no point of continuing
							}

							//make sure zapper isn't already in a call
							state currentState = sdinfo[zapperMediaFd];
							if(currentState != SOCKMEDIAIDLE)
							{
								string busy = to_string(now) + "|ring|busy|" + zapper;
								write2Client(busy, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_CALL, busy, touma, OUTBOUNDLOG, ip, iterationKey));
								continue; //not really invalid either but can't continue any further at this point
							}

							//make sure touma didn't accidentally dial himself
							if(touma == zapper)
							{
								string busy = to_string(now) + "|ring|busy|" + zapper; //ye olde landline did this
								write2Client(busy, sdssl, iterationKey);
								busy = "(self dialed) " + busy;
								userUtils->insertLog(Log(TAG_CALL, busy, touma, OUTBOUNDLOG, ip, iterationKey));
								continue; //not really invalid either but can't continue any further at this point
							}

							//setup the media fd statuses
							sdinfo[zapperMediaFd] = SOCKMEDIADIALING;
							sdinfo[toumaMediaFd] = SOCKMEDIADIALING;
							liveList[zapper] = touma;
							liveList[touma] = zapper;

							//tell touma that zapper is being rung
							string notifyTouma = to_string(now) + "|ring|available|" + zapper;
							write2Client(notifyTouma, sdssl, iterationKey);
							userUtils->insertLog(Log(TAG_CALL, notifyTouma, touma, OUTBOUNDLOG, ip, iterationKey));
			
							//tell zapper touma wants to call her
							string notifyZapper = to_string(now) + "|ring|incoming|" + touma;
							SSL *zapperssl = clientssl[zapperCmdFd];
							write2Client(notifyZapper, zapperssl, iterationKey);
							string zapperip = ipFromSd(zapperCmdFd);
							userUtils->insertLog(Log(TAG_CALL, notifyZapper, zapper, OUTBOUNDLOG, ip, iterationKey));
						}
						else if (command == "lookup")
						{//timestamp|lookup|who|fromkey
							string who = commandContents.at(2);
							string from = user;
							userUtils->insertLog(Log(TAG_LOOKUP, originalBufferCmd, from, INBOUNDLOG, ip, iterationKey));

							string exists = (userUtils->doesUserExist(who)) ? "exists" : "doesntexist";
							string resp = to_string(now) + "|lookup|" + who + "|" + exists;
							write2Client(resp, sdssl, iterationKey);
							userUtils->insertLog(Log(TAG_LOOKUP, resp, from, OUTBOUNDLOG, ip, iterationKey));
						}

						//variables written when zapper accepets touma's call
						//command will come from zapper's cmd fd
						else if (command == "accept")
						{//timestamp|accept|touma|zapperkey
							string zapper = user;
							string touma = commandContents.at(2);
							userUtils->insertLog(Log(TAG_ACCEPT, originalBufferCmd, zapper, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(zapper, touma))
							{
								string error = touma + " never made a call request to " + zapper;
								userUtils->insertLog(Log(TAG_ACCEPT, error, zapper, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_ACCEPT, invalid, zapper, OUTBOUNDLOG, ip , iterationKey));
								continue;
							}

							int zapperMediaFd = userUtils->userFd(zapper, MEDIA);
							int toumaMediaFd = userUtils->userFd(touma, MEDIA);
							sdinfo[zapperMediaFd] = SOCKMEDIALIVE;
							sdinfo[toumaMediaFd] = SOCKMEDIALIVE;

							string *pointer = new string(touma);
							pthread_t *callThread = (pthread_t*)malloc(sizeof(pthread_t));
							pthreads[touma] = callThread;
							pthreads[zapper] = callThread;
							pthread_create(callThread, NULL, callThreadFx, (void*)pointer);

							//tell touma zapper accepted his call request										
							//	AND confirm to touma, it's zapper he's being connected with
							int toumaCmdFd = userUtils->userFd(touma, COMMAND);
							SSL *toumaCmdSsl = clientssl[toumaCmdFd];
							string toumaResp = to_string(now) + "|call|start|" + zapper;
							write2Client(toumaResp, toumaCmdSsl, iterationKey);
							userUtils->insertLog(Log(TAG_ACCEPT, toumaResp, touma, OUTBOUNDLOG, ipFromSd(toumaCmdFd), iterationKey));

							//confirm to zapper she's being connected to touma
							string zapperResp = to_string(now) + "|call|start|" + touma;
							write2Client(zapperResp, sdssl, iterationKey);
							userUtils->insertLog(Log(TAG_ACCEPT, zapperResp, zapper, OUTBOUNDLOG, ip, iterationKey));
						}

						//variables modeled after setup touma calling zapper for easier readability
						//reject command would come from zapper's cmd fd
						else if (command == "reject")
						{//timestamp|reject|touma|zapperkey
							string zapper = user;
							string touma = commandContents.at(2);
							userUtils->insertLog(Log(TAG_REJECT, originalBufferCmd, zapper, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(zapper, touma))
							{
								string error = touma + " never made a call request to " + zapper;
								userUtils->insertLog(Log(TAG_REJECT, error, zapper, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_REJECT, invalid, zapper, OUTBOUNDLOG, ip , iterationKey));
								continue;
							}

							//set touma's and zapper's media socket state back to idle
							int toumaMediaFd = userUtils->userFd(touma, MEDIA);
							int zapperMediaFd = userUtils->userFd(zapper, MEDIA);
							sdinfo[toumaMediaFd] = SOCKMEDIAIDLE;
							sdinfo[zapperMediaFd] = SOCKMEDIAIDLE;
							liveList.erase(touma);
							liveList.erase(zapper);

							//tell touma his call was rejected
							int toumaCmdFd = userUtils->userFd(touma, COMMAND);
							SSL *toumaCmdSsl = clientssl[toumaCmdFd];
							string resp = to_string(now) + "|call|reject|" + zapper;
							write2Client(resp, toumaCmdSsl, iterationKey);
							userUtils->insertLog(Log(TAG_REJECT, resp, touma, OUTBOUNDLOG, ipFromSd(toumaCmdFd), iterationKey));
						}
						//call timeout: zapper hasn't answer touma's call request in the 1 minute ring time
						//cancel the call... YOU MUST tell the server the call is cancelled so it can reset the media fd states
						//nothing has to be sent to touma because his phone will automatically take care of itself
						//	to back back to the home screen
						else if(command =="timeout")
						{//timestamp|timeout|zapper|toumakey
							string zapper = commandContents.at(2);
							string touma = user;
							userUtils->insertLog(Log(TAG_TIMEOUT, originalBufferCmd, touma, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(touma, zapper))
							{
								string error = touma + " never called " + zapper + " so there is nothing to timeout";
								userUtils->insertLog(Log(TAG_TIMEOUT, error, touma, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_TIMEOUT, invalid, touma, OUTBOUNDLOG, ip, iterationKey));
								continue;
							}

							//set touma's and zapper's media socket state back to idle
							int toumaMediaFd = userUtils->userFd(touma, MEDIA);
							int zapperMediaFd = userUtils->userFd(zapper, MEDIA);
							sdinfo[toumaMediaFd] = SOCKMEDIAIDLE;
							sdinfo[zapperMediaFd] = SOCKMEDIAIDLE;
							liveList.erase(touma);
							liveList.erase(zapper);

							//tell zapper that time's up for answering touma's call
							string resp = to_string(now) + "|call|end|" + touma;
							int zapperCmdFd = userUtils->userFd(zapper, COMMAND);
							SSL *zapperCmdSsl = clientssl[zapperCmdFd];
							write2Client(resp, zapperCmdSsl, iterationKey);
							userUtils->insertLog(Log(TAG_TIMEOUT, resp, zapper, OUTBOUNDLOG, ipFromSd(zapperCmdFd), iterationKey));
						}
						else //commandContents[1] is not a known command... something fishy???
						{
							userUtils->insertLog(Log(TAG_BADCMD, originalBufferCmd, userUtils->userFromFd(sd, COMMAND), INBOUNDLOG, ip, iterationKey));
						}
					}
					catch(invalid_argument &badarg)
					{//timestamp couldn't be parsed. assume someone is trying something fishy
						string user = userUtils->userFromFd(sd, COMMAND);
						userUtils->insertLog(Log(TAG_BADCMD, originalBufferCmd, user, INBOUNDLOG, ip, iterationKey));

						string error =  "INVALID ARGUMENT EXCEPTION: (uint64_t)stoull (string too long) could not parse timestamp";
						userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

						string invalid = to_string(now) + "|resp|invalid|command";
						write2Client(invalid, sdssl, iterationKey);
						userUtils->insertLog(Log(TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip, iterationKey));
					}
					catch(out_of_range &exrange)
					{
						string user = userUtils->userFromFd(sd, COMMAND);
						userUtils->insertLog(Log(TAG_BADCMD, originalBufferCmd, user, INBOUNDLOG, ip, iterationKey));

						string error = "OUT OF RANGE (vector<string> parsed from command) EXCEPTION: client sent a misformed command";
						userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

						string invalid = to_string(now) + "|resp|invalid|command";
						write2Client(invalid, sdssl, iterationKey);
						userUtils->insertLog(Log(TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip, iterationKey));
					}
				}
				else if(sdstate == SOCKMEDIANEW)
				{//timestamp|sessionkey (of the user this media fd should be registered/associated to)
					//workaround for jclient sending first byte of a command separately
					//after the initial login
					string bufferString(inputBuffer);

					//what was previously a workaround now has an official purpose: heartbeat/ping ignore byte
					if(bufferString == JBYTE)
					{
#ifdef VERBOSE
						cout << "Got a " << JBYTE << " cap for media sd " << sd << "\n";
#endif
						continue;
					}
					vector<string> commandContents = parse(inputBuffer);
					string originalBufferContents(inputBuffer);
#ifndef VERBOSE //don't leak session keys here either
					originalBufferContents = commandContents.at(0) + "|" + SESSION_KEY_PLACEHOLDER;
#endif
					string ip = ipFromSd(sd);
					//need to write the string to the db before it gets mutilated by strtok in parse(bufferMedia)
					userUtils->insertLog(Log(TAG_MEDIANEW, originalBufferContents, DONTKNOW, INBOUNDLOG, ip, iterationKey));

					try
					{
						string sessionkey = commandContents.at(1);
						string intendedUser = userUtils->userFromSessionKey(sessionkey);

						//check timestamp is ok
						time_t now = time(NULL);
						uint64_t timestamp = (uint64_t)stoull(commandContents.at(0));
						uint64_t fivemins = 60*MARGIN_OF_ERROR;
						uint64_t timeDifference = max((uint64_t)now, timestamp) - min((uint64_t)now, timestamp);
						if(timeDifference > fivemins)
						{
							uint64_t mins = timeDifference/60;
							uint64_t seconds = timeDifference - mins*60;
							string error = "timestamp " + to_string(mins) + ":" + to_string(seconds) + " outside " + to_string(MARGIN_OF_ERROR) + "min window of error";
							userUtils->insertLog(Log(TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							continue;
						}

						//check session key belongs to a signed in user
						if(intendedUser == "")
						{
							string error = "user cannot be identified from session id";
							userUtils->insertLog(Log(TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							continue;
						}
						string message = "According to the session id, the media socket is for: " + intendedUser;
						userUtils->insertLog(Log(TAG_MEDIANEW, message, intendedUser, INBOUNDLOG, ip, iterationKey));

						//get the user's command fd to do an ip lookup of which ip the command fd is associated with
						int cmdfd = userUtils->userFd(intendedUser, COMMAND);
						if(cmdfd == 0)
						{//with a valid timestamp, valid session key, there is no cmd fd for this user??? how??? you must log in through a cmd fd to get a sessionid
							string error = "(possible bug) valid timestamp and session key but " + intendedUser + " has no command fd. can't continue association of media socket";
							userUtils->insertLog(Log(TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							continue;
						}

						//besides presenting the right session key to associate with the user (which could be a lucky guess)
						//	try and match the ip address of the media and command. not a 100% guarantee still, but if this
						//	fails, that is at least another way to figure out something isn't right.	
						// https://stackoverflow.com/questions/20472072/c-socket-get-ip-adress-from-filedescriptor-returned-from-accept
						struct sockaddr_in thisfd;
						socklen_t thisfdSize = sizeof(struct sockaddr_in);
						getpeername(sd, (struct sockaddr*) &thisfd, &thisfdSize);
						int thisfdip = thisfd.sin_addr.s_addr;

						struct sockaddr_in cmdFdInfo;
						socklen_t cmdInfoSize = sizeof(struct sockaddr_in);
						getpeername(cmdfd, (struct sockaddr*) &cmdFdInfo, &cmdInfoSize);
						int cmdip = cmdFdInfo.sin_addr.s_addr;

						if(thisfdip != cmdip)
						{//valid timestamp, valid session key, session key has command fd... but the media port association came from a different ip than the command fd...??? HOW??? all requests come from a cell phone app with 1 ip...
							string error = "SOMETHING IS REALLY WRONG. with a valid timestamp, session key, and a command fd associated with the session key, the request to associate the media fd is coming from another ip???\n";
							error = error + " last registered from ip address:" + string(inet_ntoa(cmdFdInfo.sin_addr)) + "\n";
							error = error + " is CURRENTLY registering from ip address: " + string(inet_ntoa(thisfd.sin_addr));
							userUtils->insertLog(Log(TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							continue;
						}
						userUtils->setFd(sessionkey, sd, MEDIA);
						sdinfo[sd] = SOCKMEDIAIDLE;

					}
					catch(invalid_argument &badarg)
					{
						string error = "can't get timestamp when trying establish which client a media socket should go to";
						userUtils->insertLog(Log(TAG_MEDIANEW, error, DONTKNOW, ERRORLOG, ip, iterationKey));
					}
					catch(out_of_range &exrange)
					{
						string error = "client sent a misformed media port association request, out of range exception";
						userUtils->insertLog(Log(TAG_MEDIANEW, error, DONTKNOW, ERRORLOG, ip, iterationKey));
					}
				}
#ifdef VERBOSE
				else if(sdstate == SOCKMEDIAIDLE)
				{
					cout << "received data on an established media socket. ignore it\n";
#ifdef JCALLDIAG
					cout << "Got : " << inputBuffer << "\n";
#endif
				}
				else if (sdstate == SOCKMEDIADIALING)
				{
					cout << "received data on a media socket waiting for a call accept\n";
#ifdef JCALLDIAG
					cout << "Got : " << inputBuffer << "\n";
#endif
				}
#endif //VERBOSE

			}// if FD_ISSET : figure out command or voice and handle appropriately
		}// for loop going through the fd set

		//now that all fds are finished inspecting, remove any of them that are dead.
		//don't mess with the map contents while the iterator is live.
		//removing while runnning causes segfaults because if the removed item gets iterated over after removal
		//it's no longer there so you get a segfault
		pthread_mutex_lock(&removalsMutex);
		if(removals.size() > 0)
		{
#ifdef VERBOSE
			cout << "Removing " << removals.size() << " dead/leftover sockets\n";
#endif
			for(auto rmit = removals.begin(); rmit != removals.end(); ++rmit)
			{
				int kickout = *rmit;
				if(clientssl.count(kickout) > 0)
				{
					removeClient(kickout);
				}
			}
			removals.clear();
		}
		pthread_mutex_unlock(&removalsMutex);
		//if a call thread wants to add dead media fds while the cleanup is running it will have
		//	to wait for the next round. if that next round takes forever to come, that's ok.
		//	the call thread quits at the first sign of trouble so nobody should be unhappy of a late
		//	cleanup.
#ifdef VERBOSE
		cout << "_____________________________________\n_________________________________\n";
#endif
	}

	//stop user utilities
	UserUtils *instance = UserUtils::getInstance();
	instance->killInstance();

	//openssl stuff
	SSL_CTX_free(sslcontext);
	ERR_free_strings();
	EVP_cleanup();
	
	//close ports
	close(cmdFD);
	close(mediaFD);
	return 0; 
}

void* callThreadFx(void *ptr)
{
	//establish the 2 people this thread is taking care of and free the pointer
	string *personaPtr = (string*)ptr;
	string persona = *personaPtr;
	delete(personaPtr);
	string personb = liveList[persona];

	//the usual setup
	uint64_t iterationKey;

	//convoluted char buffer for turning into a string for a weird sigabrt that happens
	//	if directly pulling the string from the vector of pairs
	string sendDrop = "";
	char sendDropBuffer[BUFFERSIZE];
	sendDropBuffer[0] = 0;
	bool quit = false;

	while(true)
	{
		//double check a's and b's media fds
		int amedia = userUtils->userFd(persona, MEDIA);
		int bmedia = userUtils->userFd(personb, MEDIA);
		int maxmedia = (amedia > bmedia) ? amedia : bmedia;
		vector<pair<int, string>> mediafds;
		mediafds.push_back(pair<int, string>(amedia, persona));
		mediafds.push_back(pair<int, string>(bmedia, personb));

		//setup fd sets
		fd_set readfds, writefds;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_SET(amedia, &readfds);
		FD_SET(bmedia, &readfds);
		FD_SET(amedia, &writefds);
		FD_SET(bmedia, &writefds);

		iterationKey = dist(mt);

		int sockets = select(maxmedia+1, &readfds, NULL, NULL, NULL);
		if(sockets < 0)
		{
			string error = "read fds select system call error";
			userUtils->insertLog(Log(TAG_CALLTHREAD, error, SELF, ERRORLOG, SELFIP, iterationKey));
			exit(1); //stop the whole thing. let it all come crashing down
			//assuming params ok only a kernel error will produce sockets < 0.
			//exit and cut your losses
		}
		sockets = select(maxmedia+1, NULL, &writefds, NULL, NULL);
		if(sockets < 0)
		{
			string error = "write fds select system call error";
			userUtils->insertLog(Log(TAG_CALLTHREAD, error, SELF, ERRORLOG, SELFIP, iterationKey));
			exit(1);
		}

		for(int iterator=0; iterator<2; iterator++) //there's only 2 media fds
		{
			int other = 1-iterator;
			int iteratorfd = mediafds.at(iterator).first;
			int otherfd = mediafds.at(other).first;

			if(FD_ISSET(iteratorfd, &readfds))
			{
				char buffer[BUFFERSIZE];
				int amount = readSSL(clientssl[iteratorfd], buffer, iterationKey);
				if(amount == 0)
				{//my fd is dead, send the other person a call end, mark mine for removal
					//whether mine is dead because i want the call to end or by accident, the result is the same
#ifdef VERBOSE
					cout << mediafds.at(iterator).second << "'s media fd died\n";
#endif
					mediafds.at(other).second.copy(sendDropBuffer, mediafds.at(other).second.length(), 0);
					pthread_mutex_lock(&removalsMutex);
					removals.push_back(iteratorfd);
					pthread_mutex_unlock(&removalsMutex);
					quit = true;
				}

				if(FD_ISSET(otherfd, &writefds)) //can i write to the other person?
				{
					int err = SSL_write(clientssl[otherfd], buffer, amount);
					if(err <= 0)
					{//something bad happened when writing to the other person. increase the fail count
						failCount[otherfd]++;
					}
				}
				else //i can't write to the other person, increase the fail count
				{
					failCount[otherfd]++;
				}

				//have there been too many problems writing to this person?
				if(failCount[otherfd] > FAILMAX)
				{//if so, send me a drop and remove the other person's media fd
#ifdef VERBOSE
					cout << mediafds.at(other).second << "'s media fd has had too many problems\n";
#endif
					mediafds.at(iteratorfd).second.copy(sendDropBuffer, mediafds.at(iteratorfd).second.length(), 0);
					pthread_mutex_lock(&removalsMutex);
					removals.push_back(otherfd);
					pthread_mutex_unlock(&removalsMutex);

					string ip = ipFromSd(otherfd);
					string recepientName = mediafds.at(other).second;
					string error = "reached maximum media socket write failure of: " + to_string(FAILMAX);
					userUtils->insertLog(Log(TAG_MEDIACALL, error, recepientName, ERRORLOG, ip, iterationKey));
					quit = true;
				}
			}
		}

		if(quit)
		{
			break;
		}
	}

	//only way to exit the loop is if somebody's socket dies, whether on purpose or not
	sendDrop = string(sendDropBuffer);
	int command = userUtils->userFd(sendDrop, COMMAND);
	int media = userUtils->userFd(sendDrop, MEDIA);

	//logging related stuff
	string ip = ipFromSd(command);

	//reset the media connection state
	sdinfo[media] = SOCKMEDIAIDLE;

	//drop the call for the user
	time_t now = time(NULL);
	string other = (sendDrop == persona) ? personb : persona;

	//write to the person who got dropped's command fd that the call was dropped
	string end = to_string(now) + "|call|end|" + other;
	SSL *cmdSsl = clientssl[command];
	write2Client(end, cmdSsl, iterationKey);
	userUtils->insertLog(Log(TAG_CALLTHREAD, end, sendDrop, OUTBOUNDLOG, ip, iterationKey));

	return NULL;
}


//use a vector to prevent reading out of bounds
vector<string> parse(char command[])
{
//timestamp|login1|username
//timestamp|login2|username|challenge_decrypted

//timestamp|call|otheruser|sessionkey
//timestamp|lookup|user|sessionkey
//timestamp|reject|user|sessionkey
//timestamp|accept|user|sessionkey
//timestamp|timeout|user|sessionkey

//timestamp|sessionkey : for registering media port
	char *token;
	int i = 0;
	vector<string> result;
	token = strtok(command, "|");
	while(token != NULL && i < 4)
	{
		result.push_back(string(token));
		token = strtok(NULL, "|");
		i++;
	}
	return result;
}

// sd: a client's socket descriptor
// to make things easier, this function will attempt to find both the media and cmd fd
//	for the user to be removed.
void removeClient(int sd)
{
	string uname = userUtils->userFromFd(sd, COMMAND); //make a lucky guess you got the command fd
	int media, cmd;

	//make the assumption. if it's right remove both. if it's wrong then... it's still right. remove only the media
	cmd = sd;
	media = userUtils->userFd(uname, MEDIA);


#ifdef VERBOSE
	cout << "removing " << uname << "'s socket descriptors (cmd, media): (" << cmd << "," << media << ")\n";
#endif

	if (cmd > 4) //0 stdin, 1 stdout, 2 stderr, 3 command receive, 4, media receive
	{

		sdinfo.erase(cmd);
		failCount.erase(cmd);

		if (clientssl.count(cmd) > 0)
		{
			SSL_shutdown(clientssl[cmd]);
			SSL_free(clientssl[cmd]);
			shutdown(cmd, 2);
			close(cmd);
			clientssl.erase(cmd);
		}
	}

	if (media > 4)
	{

		sdinfo.erase(media);
		failCount.erase(media);

		if (clientssl.count(media) > 0)
		{
			SSL_shutdown(clientssl[media]);
			SSL_free(clientssl[media]);
			shutdown(media, 2);
			close(media);
			clientssl.erase(media);
		}
	}

	//if this really is a media fd being removed, remove the live call stuff and free its pthread
	string medaiaFdOwner = userUtils->userFromFd(cmd, MEDIA);
	if(pthreads.count(medaiaFdOwner) > 0)
	{
		string other = liveList[medaiaFdOwner];
		pthread_t *callThread = pthreads[medaiaFdOwner];
		pthreads.erase(medaiaFdOwner);
		pthreads.erase(other);
		liveList.erase(medaiaFdOwner);
		liveList.erase(other);
		free(callThread);
	}

	//incase of crash, there will be no entires in the hash table and tree. skip these pairs and just flush out
	//	the irrelevant db info
	userUtils->clearSession(uname);
}

//before doing an accept, reject, end command check to see if it's for a real call
//	or someone trying to get smart with the server
bool isRealCall(string persona, string personb)
{
	string prefix =  "call between " + persona + " && " + personb + ": ";

	//check if A and B even have media FDs
	int afd = userUtils->userFd(persona, MEDIA);
	int bfd = userUtils->userFd(personb, MEDIA);
	if(afd == 0)
	{
#ifdef VERBOSE
		cout << prefix << persona << " doesn't even have a media fd\n";
#endif
		return false;
	}
	if(bfd == 0)
	{
#ifdef VERBOSE
		cout << prefix << personb << " doesn't even have a media fd\n";
#endif
		return false;
	}

	//check if either is in or waiting for a call
	state astatus = sdinfo[afd];
	if(!((astatus ==  SOCKMEDIADIALING) || (astatus == SOCKMEDIALIVE)))
	{
#ifdef VERBOSE
		cout << prefix << persona << " isn't expecting or in a call\n";
#endif
		return false;
	}

	state bstatus = sdinfo[bfd];
	if(!((bstatus == SOCKMEDIADIALING) || (bstatus == SOCKMEDIALIVE)))
	{
#ifdef VERBOSE
		cout << prefix << personb << " isn't expecting or in a call\n";
#endif
		return false;
	}

	//the moment of truth
	//	if you've made it this far your media fd states must make it so these 2 must
	//	be on the live list
	bool result = (liveList[persona] == personb) && (liveList[personb] == persona);
#ifdef VERBOSE
	cout << prefix << "is a real call???: " << result << "\n";
#endif
	return result;
}


// write a message to a client
void write2Client(string response, SSL *respSsl, uint64_t relatedKey)
{
	int errValue = SSL_write(respSsl, response.c_str(), response.size());
	if(errValue <= 0)
	{
		int socket = SSL_get_fd(respSsl);
		string user = userUtils->userFromFd(socket, COMMAND);
		string error = "ssl_write returned an error of: " + to_string(errValue) + " while trying to write to the COMMAND socket";
		string ip = ipFromSd(socket);
		userUtils->insertLog(Log(TAG_SSLCMD, error, user, ERRORLOG, ip, relatedKey));
	}
}

string ipFromSd(int sd)
{
	struct sockaddr_in thisfd;
	socklen_t thisfdSize = sizeof(struct sockaddr_in);
	getpeername(sd, (struct sockaddr*) &thisfd, &thisfdSize);
	return string(inet_ntoa(thisfd.sin_addr));
}

string stringify(unsigned char *bytes, int length)
{
	string result = "";
	for(int i=0; i<length; i++)
	{
		string number = to_string(bytes[i]);
		if(bytes[i] < 10)
		{//for 1,2,3 to keep everything as 3 digit #s make it 001, 002 etc
			number = "00" + number;
		}
		else if (bytes[i] < 100)
		{//for 10,11,12 make it 010,011,012
			number = "0" + number;
		}
		result = result + number;
	}
	return result;
}

int readSSL(SSL *sdssl, char inputBuffer[], uint64_t iterationKey)
{
	//read from the socket into the buffer
	int bufferRead=0, totalRead=0;
	bool waiting;
	bzero(inputBuffer, BUFFERSIZE+1);
	do
	{//wait for the input chunk to come in first before doing something
		totalRead = SSL_read(sdssl, inputBuffer, BUFFERSIZE-bufferRead);
		if(totalRead > 0)
		{
			bufferRead = bufferRead + totalRead;
		}
		int sslerr = SSL_get_error(sdssl, totalRead);
		switch (sslerr)
		{
			case SSL_ERROR_NONE:
				waiting = false;
				break;
			//other cases when necessary. right now only no error signals a successful read
		}
	} while(waiting && SSL_pending(sdssl));

	///SSL_read return 0 = dead socket
	if(totalRead == 0)
	{
		int sd = SSL_get_fd(sdssl);
		string user;
		if(sdinfo[sd] == SOCKCMD)
		{
			user = userUtils->userFromFd(sd, COMMAND);
		}
		else
		{
			user = userUtils->userFromFd(sd, MEDIA);
		}
		string ip = ipFromSd(sd);
		string error = "socket has died";
		userUtils->insertLog(Log(TAG_DEADSOCK, error, user, ERRORLOG, ip, iterationKey));
	}
	return totalRead;
}








