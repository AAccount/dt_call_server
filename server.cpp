#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

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

#include <string>
#include <unordered_map> //hash table
#include <vector>
#include <set>
#include <random>
#include <unordered_set>
#include <mutex>
#include <condition_variable>
#include <pthread.h>
#include <algorithm>

#include "Log.hpp"
#include "UserUtils.hpp"

using namespace std;

struct timeval writeTimeout;

//information on what each socket descriptor is (command, media) and what it's supposed to be doing if it's a media socket
unordered_map<int, int> sdinfo; 

//associates socket descriptors to their ssl structs
unordered_map<int, SSL*>clientssl;
mutex clientsslMutex; //for race conditions when the main thread erases an entry the live thread was just looking at

//fail counts of each socket descriptor. if there are too many fails then remove the socket.
//most likely to be used by media sockets during calls. media socket gets reset after a call anyways
//so any fails are going to come from the current call
unordered_map<int, int> failCount;

//list of live call media fds the call thread should be paying attention to
unordered_set<int> liveFds;
mutex liveMutex;

//variables to wake up the call thread when it has stuff to take care of
mutex callThreadWakeup;
condition_variable callThreadCv;

//list of fds that main should remove at the end of each of its rounds
set<int> removals;
mutex removalsModMutex;

UserUtils *userUtils = UserUtils::getInstance();

int main(int argc, char *argv[])
{
	//setup random number generator for the log relation key (a random number that related logs can use)
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<uint64_t> dist (0, (uint64_t)9223372036854775807);
	uint64_t initkey = dist(mt);

	userUtils->insertLog(Log(TAG_INIT, "starting call operator", SELF, SYSTEMLOG, SELFIP, initkey));

#ifdef JSTOPMEDIA
	userUtils->insertLog(Log(TAG_INIT, "compiled with JSTOPMEDIA flag", SELF, SYSTEMLOG , SELFIP, initkey));
#endif
	
	int cmdFD, incomingCmd, cmdPort = DEFAULTCMD; //command port stuff
	int mediaFD, incomingMedia, mediaPort = DEFAULTMEDIA, bufferRead; //media port stuff
	int amountRead; //for counting how much was ssl read
	int maxsd, sd; //select related vars
	SSL *sdssl; //used for iterating through the ordered map
	char inputBuffer[BUFFERSIZE+1];

	string publicKeyFile, privateKeyFile, ciphers = DEFAULTCIPHERS, dhfile = "";

	//use a helper function to read the config file
	readServerConfig(&cmdPort, &mediaPort, &publicKeyFile, &privateKeyFile, &ciphers, &dhfile, userUtils, initkey);

	//helper to setup the ssl context
	SSL_CTX *sslcontext = setupOpenSSL(ciphers, privateKeyFile, publicKeyFile, dhfile, userUtils, initkey);

	//socket read timeout option
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = READTIMEOUT;
	//write select timeout
	writeTimeout.tv_sec = 0;
	writeTimeout.tv_usec = WSELECTTIMEOUT;

	//helper to setup the sockets
	struct sockaddr_in serv_cmd, serv_media, cli_addr;
	setupListeningSocket(&timeout, &cmdFD, &serv_cmd, cmdPort, userUtils, initkey);
	setupListeningSocket(&timeout, &mediaFD, &serv_media, mediaPort, userUtils, initkey);

	socklen_t clilen = sizeof(cli_addr);

	//sigpipe is thrown for closing the broken connection. it's gonna happen for a voip server handling mobile clients
	//what're you gonna do about it... IGNORE IT!!
	sigset_t ignorePipe;
	sigemptyset(&ignorePipe);
	sigaddset(&ignorePipe, SIGPIPE);
	if(pthread_sigmask(SIG_BLOCK, &ignorePipe, NULL) != 0)
	{
		perror("Cannot block sigpipe. Call server will not be reliable.");
		exit(1);
	}

	fd_set readfds;
	fd_set writefds;

	//start the call thread
	pthread_t liveCalls;
	if(pthread_create(&liveCalls, NULL, callThreadFx, NULL) != 0)
	{
		perror("Cannot create call thread.");
		exit(1);
	}
	pthread_setname_np(liveCalls, "LiveCalls");

	while(true) //forever
	{
#ifdef VERBOSE
		cout << "------------------------------------------\n----------------------------------------\n";
#endif
		FD_ZERO(&readfds);
		FD_SET(cmdFD, &readfds);
		FD_SET(mediaFD, &readfds);
		FD_ZERO(&writefds);
		maxsd = (cmdFD > mediaFD) ? cmdFD : mediaFD; //quick 1 liner for determining the bigger sd

		for(auto it = clientssl.begin(); it != clientssl.end(); ++it)
		{
			sd = it->first;
			int state = sdinfo[sd];
			if (state == SOCKCMD || state == SOCKMEDIANEW || state == SOCKMEDIAIDLE)
			{//main no longer in charge of live call media sockets
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
			return 1;
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
			return 1;
		}
#ifdef VERBOSE
		cout << "select has " << sockets << " sockets ready for writing\n";
#endif

		//check for a new incoming connection on command port
		if(FD_ISSET(cmdFD, &readfds))
		{
			uint64_t relatedKey = dist(mt);
			setupSslClient(cmdFD, SOCKCMD, &cli_addr, clilen, &timeout, sslcontext, userUtils, relatedKey);
		}

		//check for a new incoming connection on media port
		if(FD_ISSET(mediaFD, &readfds))
		{
			uint64_t relatedKey = dist(mt);
			setupSslClient(mediaFD, SOCKMEDIANEW, &cli_addr, clilen, &timeout, sslcontext, userUtils, relatedKey);
		}

		//check for data on an existing connection
		for(auto it = clientssl.begin(); it != clientssl.end(); ++it)
		{//figure out if it's a command, or voice data. handle appropriately

			//get the socket descriptor and associated ssl struct from the iterator round
			sd = it->first;
			sdssl = it->second;
			if(FD_ISSET(sd, &readfds))
			{
#ifdef VERBOSE
				cout << "socket descriptor: " << sd << " was marked as set\n";
#endif
				uint64_t iterationKey = dist(mt);
				amountRead = readSSLSocket(sdssl, inputBuffer, iterationKey); //size is the standard buffer size in const.h
				if(amountRead == 0)
				{
					removalsModMutex.lock();
					removals.insert(sd);
					removalsModMutex.unlock();
					continue;
				}

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

				int sdstate = sdinfo[sd];
				if(sdstate == SOCKCMD)
				{
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
							string user = userUtils->userFromFd(sd, COMMAND);
							if(originalBufferCmd.find("login") == string::npos)
							{//don't accidentally leak passwords for bad login timestamps
								error = error + " (" + originalBufferCmd + ")";
							}
							else
							{
								error = error + commandContents.at(0) + "|login|" + user + "|????????"; //never store plain text passwords ANYWHERE
							}
							userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

							//send the rejection to the client
							string invalid = to_string(now) + "|resp|invalid|command\n";
							write2Client(invalid, sdssl, iterationKey);
							continue;
						}

						if(command == "login") //you can do string comparison like this in c++
						{//timestamp|login|username|passwd
							string username = commandContents.at(2);
							string plaintext = commandContents.at(3);
							string ip = ipFromSd(sd);
							string censoredInput = commandContents.at(0) + "|login|" + username + "|????????"; //never store plain text passwords ANYWHERE
							userUtils->insertLog(Log(TAG_LOGIN, censoredInput, username, INBOUNDLOG, ip, iterationKey));

							int oldcmd = userUtils->userFd(username, COMMAND);
							if(oldcmd > 0)
							{//remove old SSL structs to prevent memory leak
#ifdef VERBOSE
								cout << "previous command socket/SSL* exists, will remove\n";
#endif
								removalsModMutex.lock();
								removals.insert(oldcmd);
								removalsModMutex.unlock();
							}

							int oldmedia = userUtils->userFd(username, MEDIA);
							if(oldmedia > 0)
							{//remove old SSL structs to prevent memory leak
#ifdef VERBOSE
								cout << "previous meida socket/SSL* exists, will remove\n";
#endif
								removalsModMutex.lock();
								removals.insert(oldmedia);
								removalsModMutex.unlock();
							}

							uint64_t sessionid = userUtils->authenticate(username, plaintext);
							if(sessionid == 0)
							{
								//for the user however, give no hints about what went wrong in case of brute force
								string invalid = to_string(now) + "|resp|invalid|command\n";
								userUtils->insertLog(Log(TAG_LOGIN, invalid, username, OUTBOUNDLOG, ip, iterationKey));
								write2Client(invalid, sdssl, iterationKey);
								continue;
							}

							//record a succesful login and response sent
							userUtils->setFd(sessionid, sd, COMMAND);
							string resp = to_string(now) + "|resp|login|" + to_string(sessionid);
							write2Client(resp, sdssl, iterationKey);
							userUtils->insertLog(Log(TAG_LOGIN, resp, username, OUTBOUNDLOG, ip, iterationKey));
						}

						//variables written from touma calling zapper perspective
						//command will come from touma's cmd fd
						else if (command == "call")
						{//timestamp|call|zapper|toumaid

							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string zapper = commandContents.at(2);
							string touma = userUtils->userFromSessionid(sessionid);
							userUtils->insertLog(Log(TAG_CALL, originalBufferCmd, touma, INBOUNDLOG, ip, iterationKey));

							if(!userUtils->verifySessionid(sessionid, sd))
							{
								string error = " INVALID SESSION ID. refusing to start call";
								userUtils->insertLog(Log(TAG_CALL, error, touma, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_CALL, invalid, touma, OUTBOUNDLOG, ip, iterationKey));
								continue;
							}

							//double check touma has a mediafd
							int toumaMediaFd = userUtils->userFd(touma, MEDIA);
							if(toumaMediaFd == 0)
							{
								string invalid = to_string(now) + "|resp|invalid|command\n";
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
							int currentState = sdinfo[zapperMediaFd];
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
							sdinfo[zapperMediaFd] = -toumaMediaFd;
							sdinfo[toumaMediaFd] = -zapperMediaFd;

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
						{
							string who = commandContents.at(2);
							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string from = userUtils->userFromSessionid(sessionid);
							userUtils->insertLog(Log(TAG_LOOKUP, originalBufferCmd, from, INBOUNDLOG, ip, iterationKey));

							if(!userUtils->verifySessionid(sessionid, sd))
							{
								string error = "invalid sessionid attempting to do a user lookup";
								userUtils->insertLog(Log(TAG_LOOKUP, error, from, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_LOOKUP, invalid, from, OUTBOUNDLOG, ip, iterationKey));
								continue;
							}
							string exists = (userUtils->doesUserExist(who)) ? "exists" : "doesntexist";
							string resp = to_string(now) + "|lookup|" + who + "|" + exists;
							write2Client(resp, sdssl, iterationKey);
							userUtils->insertLog(Log(TAG_LOOKUP, resp, from, OUTBOUNDLOG, ip, iterationKey));
						}

						//variables written when zapper accepets touma's call
						//command will come from zapper's cmd fd
						else if (command == "accept")
						{//timestamp|accept|touma|zapperid
							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string zapper = userUtils->userFromSessionid(sessionid);
							string touma = commandContents.at(2);
							userUtils->insertLog(Log(TAG_ACCEPT, originalBufferCmd, zapper, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(zapper, touma))
							{
								string error = touma + " never made a call request to " + zapper;
								userUtils->insertLog(Log(TAG_ACCEPT, error, zapper, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_ACCEPT, invalid, zapper, OUTBOUNDLOG, ip , iterationKey));
								continue;
							}

							int zapperMediaFd = userUtils->userFd(zapper, MEDIA);
							int toumaMediaFd = userUtils->userFd(touma, MEDIA);
							sdinfo[zapperMediaFd] = toumaMediaFd;
							sdinfo[toumaMediaFd] = zapperMediaFd;

							//set the live watch and notify
							liveMutex.lock();
							liveFds.insert(toumaMediaFd);
							liveFds.insert(zapperMediaFd);
							liveMutex.unlock();

							//wake up the live call thread if it's waiting
							lock_guard<mutex> lock(callThreadWakeup);
							callThreadCv.notify_all();

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
						{//timestamp|reject|touma|sessionid
							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string zapper = userUtils->userFromSessionid(sessionid);
							string touma = commandContents.at(2);
							userUtils->insertLog(Log(TAG_REJECT, originalBufferCmd, zapper, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(zapper, touma))
							{
								string error = touma + " never made a call request to " + zapper;
								userUtils->insertLog(Log(TAG_REJECT, error, zapper, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_REJECT, invalid, zapper, OUTBOUNDLOG, ip , iterationKey));
								continue;
							}

							//set touma's and zapper's media socket state back to idle
							int toumaMediaFd = userUtils->userFd(touma, MEDIA);
							int zapperMediaFd = userUtils->userFd(zapper, MEDIA);
							sdinfo[toumaMediaFd] = SOCKMEDIAIDLE;
							sdinfo[zapperMediaFd] = SOCKMEDIAIDLE;

							//tell touma his call was rejected
							int toumaCmdFd = userUtils->userFd(touma, COMMAND);
							SSL *toumaCmdSsl = clientssl[toumaCmdFd];
							string resp = to_string(now) + "|call|reject|" + zapper;
							write2Client(resp, toumaCmdSsl, iterationKey);
							userUtils->insertLog(Log(TAG_REJECT, resp, touma, OUTBOUNDLOG, ipFromSd(toumaCmdFd), iterationKey));
						}

						//variables modeled after setup touma calling zapper for easier readability
						//end could come from either of them
						else if (command == "end")
						{
							//timestamp|end|touma|zappersid : zapper wants to end the call with touma
							//timestamp|end|zapper|toumasid : touma wants to end the call with zapper

							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string wants2End = userUtils->userFromSessionid(sessionid);
							string stillTalking = commandContents.at(2);
							userUtils->insertLog(Log(TAG_END, originalBufferCmd, wants2End, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(wants2End, stillTalking))
							{
								string error = stillTalking + " isn't in a call with " + wants2End;
								userUtils->insertLog(Log(TAG_END, error, wants2End, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_END, invalid, wants2End, OUTBOUNDLOG, ip, iterationKey));
								continue;
							}

							//set touma's and zapper's media socket state back to idle
							int endMediaFd = userUtils->userFd(wants2End, MEDIA);
							int talkingMediaFd = userUtils->userFd(stillTalking, MEDIA);
							sdinfo[endMediaFd] = SOCKMEDIAIDLE;
							sdinfo[talkingMediaFd] = SOCKMEDIAIDLE;

							//remove the fds to the live watch
							liveMutex.lock();
							liveFds.erase(endMediaFd);
							liveFds.erase(talkingMediaFd);
							liveMutex.unlock();

							//tell the one still talking, it's time to hang up
							string resp = to_string(now) + "|call|end|" + wants2End;
							int talkingCmdFd = userUtils->userFd(stillTalking, COMMAND);
							SSL *talkingCmdSsl = clientssl[talkingCmdFd];
							write2Client(resp, talkingCmdSsl, iterationKey);
							userUtils->insertLog(Log(TAG_END, resp, stillTalking, OUTBOUNDLOG, ipFromSd(talkingCmdFd), iterationKey));
						}
						//call timeout: zapper hasn't answer touma's call request in the 1 minute ring time
						//cancel the call... YOU MUST tell the server the call is cancelled so it can reset the media fd states
						//nothing has to be sent to touma because his phone will automatically take care of itself
						//	to back back to the home screen
						else if(command =="timeout")
						{
							string zapper = commandContents.at(2);
							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string touma = userUtils->userFromSessionid(sessionid);
							userUtils->insertLog(Log(TAG_TIMEOUT, originalBufferCmd, touma, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(touma, zapper))
							{
								string error = touma + " never called " + zapper + " so there is nothing to timeout";
								userUtils->insertLog(Log(TAG_TIMEOUT, error, touma, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								userUtils->insertLog(Log(TAG_TIMEOUT, invalid, touma, OUTBOUNDLOG, ip, iterationKey));
								continue;
							}

							//set touma's and zapper's media socket state back to idle
							int toumaMediaFd = userUtils->userFd(touma, MEDIA);
							int zapperMediaFd = userUtils->userFd(zapper, MEDIA);
							sdinfo[toumaMediaFd] = SOCKMEDIAIDLE;
							sdinfo[zapperMediaFd] = SOCKMEDIAIDLE;

							//tell zapper that time's up for answering touma's call
							string resp = to_string(now) + "|ring|timeout|" + touma;
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

						string invalid = to_string(now) + "|resp|invalid|command\n";
						write2Client(invalid, sdssl, iterationKey);
						userUtils->insertLog(Log(TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip, iterationKey));
					}
					catch(out_of_range &exrange)
					{
						string user = userUtils->userFromFd(sd, COMMAND);
						userUtils->insertLog(Log(TAG_BADCMD, originalBufferCmd, user, INBOUNDLOG, ip, iterationKey));

						string error = "OUT OF RANGE (vector<string> parsed from command) EXCEPTION: client sent a misformed command";
						userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

						string invalid = to_string(now) + "|resp|invalid|command\n";
						write2Client(invalid, sdssl, iterationKey);
						userUtils->insertLog(Log(TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip, iterationKey));
					}
				}
				else if(sdstate == SOCKMEDIANEW)
				{//timestamp|sessionid (of the user this media fd should be registered/associated to)
					//workaround for jclient sending first byte of a command separately
					//after the initial login
					string bufferString(inputBuffer);

					string ip = ipFromSd(sd);
					//need to write the string to the db before it gets mutilated by strtok in parse(bufferMedia)
					userUtils->insertLog(Log(TAG_MEDIANEW, string(inputBuffer), DONTKNOW, INBOUNDLOG, ip, iterationKey));
					vector<string> commandContents = parse(inputBuffer);

					try
					{
						uint64_t sessionid = (uint64_t)stoull(commandContents.at(1));
						string intendedUser = userUtils->userFromSessionid(sessionid);

						//check timestamp is ok
						time_t now = time(NULL);
						uint64_t timestamp = (uint64_t)stoull(commandContents.at(0));
						uint64_t fivemins = 60*5;
						uint64_t timeDifference = max((uint64_t)now, timestamp) - min((uint64_t)now, timestamp);
						if(timeDifference > fivemins)
						{
							uint64_t mins = timeDifference/60;
							uint64_t seconds = timeDifference - mins*60;
							string error = "timestamp " + to_string(mins) + ":" + to_string(seconds) + " outside 5min window of error";
							userUtils->insertLog(Log(TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							continue;
						}

						//check sessionid belongs to a signed in user
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
						{//with a valid timestamp, valid sessionid, there is no cmd fd for this user??? how??? you must log in through a cmd fd to get a sessionid
							string error = "(possible bug) valid timestamp and sessionid but " + intendedUser + " has no command fd. can't continue association of media socket";
							userUtils->insertLog(Log(TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							continue;
						}

						//besides presenting the right sessionid to associate with the user (which could be a lucky guess)
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
						{//valid timestamp, valid sessionid, sessionid has command fd... but the media port association came from a different ip than the command fd...??? HOW??? all requests come from a cell phone app with 1 ip...
							string error = "SOMETHING IS REALLY WRONG. with a valid timestamp, sessionid, and a command fd associated with the sessionid, the request to associate the media fd is coming from another ip???\n";
							error = error + " last registered from ip address:" + string(inet_ntoa(cmdFdInfo.sin_addr)) + "\n";
							error = error + " is CURRENTLY registering from ip address: " + string(inet_ntoa(thisfd.sin_addr));
							userUtils->insertLog(Log(TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							continue;
						}
						userUtils->setFd(sessionid, sd, MEDIA);
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
				else if(sdstate <= SOCKMEDIAIDLE)
				{
#ifdef VERBOSE
					if(sdstate == SOCKMEDIAIDLE)
					{
						cout << "received data on an established media socket. ignore it\n";
#ifdef JCALLDIAG
						cout << "Got : " << inputBuffer << "\n";
#endif
					}
					else //if(sdstate < -3)
					{
						cout << "received data on a media socket waiting for a call accept\n";
#ifdef JCALLDIAG
						cout << "Got : " << inputBuffer << "\n";
#endif
					}
#endif //VERBOSE

				}
			}// if FD_ISSET : figure out command or voice and handle appropriately
		}// for loop going through the fd set

		//now that all fds are finished inspecting, remove any of them that are dead.
		//don't mess with the map contents while the iterator is live.
		//removing while runnning causes segfaults because if the removed item gets iterated over after removal
		//it's no longer there so you get a segfault
		removalsModMutex.lock();
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
		removalsModMutex.unlock();
#ifdef VERBOSE
		cout << "_____________________________________\n_________________________________\n";
#endif
	}

	//stop user utilities
	userUtils->killInstance();

	//openssl stuff
	SSL_CTX_free(sslcontext);
	ERR_free_strings();
	EVP_cleanup();
	
	//close ports
	close(cmdFD);
	close(mediaFD);
	return 0; 
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// live calls thread function: a mini version of the main function just for calls
/////////////////////////////////////////////////////////////////////////////////////////////////
void* callThreadFx(void *unused)
{
	//setup random number generator for the log relation key (a random number that related logs can use)
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<uint64_t> dist (0, (uint64_t)9223372036854775807);

	fd_set callReadFds;
	fd_set callWriteFds;
	int readMax=0, writeMax=0;
	char liveBuffer[BUFFERSIZE+1];

	while(true)
	{
		if(liveFds.size() == 0)
		{//if there are no live fds to watch then wait until there are some
			cout << "live call threads going to sleep\n";
			unique_lock<mutex> lock(callThreadWakeup);
			callThreadCv.wait(lock);
			lock.unlock(); //no need to keep holding on. just needed it for the wakeup call
			cout << "live calls thread woken up\n";
		}

		uint64_t iterationKey = dist(mt);

		//make a copy of the live fd list to avoid locking the whole time
		liveMutex.lock();
		vector<int> liveCopy;
		for(auto it=liveFds.begin(); it != liveFds.end(); ++it)
		{
			liveCopy.push_back(*it);
		}
		liveMutex.unlock();

		//zero out max and fd sets for a new round
		FD_ZERO(&callReadFds);
		FD_ZERO(&callWriteFds);
		readMax=0, writeMax=0;

		//setup the fd sets
		for(auto it=liveCopy.begin(); it != liveCopy.end(); ++it)
		{
			FD_SET(*it, &callReadFds);
			FD_SET(*it, &callWriteFds);
			readMax = (*it > readMax) ? *it : readMax;
			writeMax = (*it > writeMax) ? *it : writeMax;
		}

		//wait for call data to come in and figure out who call data can be written to
		if(select(readMax+1, &callReadFds, NULL, NULL, NULL) < 0)
		{
			continue;
		}
		if(select(writeMax+1, NULL, &callWriteFds, NULL, &writeTimeout) < 0)
		{
			continue;
		}

		for(auto it=liveCopy.begin(); it != liveCopy.end(); ++it)
		{
			if(FD_ISSET(*it, &callReadFds))
			{
				//make sure when going to get the SSL* out of clientssl, it doesn't vanish in between
				clientsslMutex.lock();
				if(clientssl.count(*it) == 0)
				{
					cout << "edge case of live thread select, client reset media socket, media socket cleaned up, trying to read a nonexistant socket\n";
					clientsslMutex.unlock();

					//no point of following a dead socket
					removalsModMutex.lock();
					removals.insert(*it);
					removalsModMutex.unlock();
					continue;
				}

				int amountRead = readSSLSocket(clientssl[*it], liveBuffer, iterationKey);
				clientsslMutex.unlock();

				int sdstate = sdinfo[*it];
				if(amountRead == 0)
				{
					cout << "LIVE CALL THREAD fd " << *it << " died\n";
					//nothing read, this socket is dead. add it to the removals
					removalsModMutex.lock();
					removals.insert(*it);
					removalsModMutex.unlock();

					//also stop following it on the live list
					liveMutex.lock();
					liveFds.erase(*it);
					liveMutex.unlock();
					continue; //on to the next one
				}

				if(clientssl.count(sdstate) > 0) //is the receipient still there
				{
					if(FD_ISSET(sdinfo[*it], &callWriteFds))
					{
						SSL *recepient = clientssl[sdstate];
						SSL_write(recepient, liveBuffer, amountRead);
					}
					else
					{
						//if there is no place, just drop the 32bytes of voice
						//a backlog of voice will cause a call lag. better to ask again and say "didn't catch that"
						int fails = failCount[sdstate];
						string ip = ipFromSd(sdstate); //log the ip of the socket that can't be written to
						string user = userUtils->userFromFd(sdstate, MEDIA); //log who couldn't be sent media
						string error = "couldn't write to media socket because it was not ready. failed " + to_string(fails) + " times";
						userUtils->insertLog(Log(TAG_MEDIACALL, error, user, ERRORLOG, ip, iterationKey));

						fails++;
						failCount[sdstate] = fails;
						if (fails > FAILMAX)
						{
							string error = "reached maximum media socket write failure of: " + to_string(FAILMAX);
							userUtils->insertLog(Log(TAG_MEDIACALL, error, user, ERRORLOG, ip, iterationKey));

							removalsModMutex.lock();
							removals.insert(sdstate);
							removalsModMutex.unlock();

							//stop following the receiver on the live list.
							//stop following the sender on the next round where the sender is cleaned up
							liveMutex.lock();
							liveFds.erase(sdstate);
							liveMutex.unlock();
						}
					}
				}
				else
				{
					//call drop logic: example of touma calling zapper and touma's connection dies
					//if touma's connetion dies during the current round of "select", zapper's kb of
					//media will just be lost in the above if block. it won't reach this else block yet
					//because touma will still have a media port
					//
					//if touma's connection died during a previous round of select, you cannot send
					//timestamp|call|end|touma to zapper because touma's file/socket descriptor records have
					//been removed form the database. at the present, the state of zapper'd media fd = touma media fd.
					//because the record has been removed, you can't do userUtils->userFromFd(zapper_mediafd_state, MEDIA)
					//to find out she's in a call with touma.
					//therefore you have to send a different command... the call drop command

					//logging related stuff
					string ip = ipFromSd(*it);

					//reset the media connection state
					string user = userUtils->userFromFd(*it, MEDIA);
					sdinfo[*it] = SOCKMEDIAIDLE; //no need to fear a race condition. only accept, end, drop modify media socket state

					//stop following the sender now that he's idle
					liveMutex.lock();
					liveFds.erase(*it);
					liveMutex.unlock();

					//drop the call for the user
					time_t now = time(NULL);
					uint64_t sessionid = userUtils->userSessionId(user);
					if (sessionid == 0)
					{
						string error = "call was dropped but the user had no session id?? possible bug";
						userUtils->insertLog(Log(TAG_MEDIACALL, error, user, ERRORLOG, ip, iterationKey));
						continue;
					}

					//write to the person who got dropped's command fd that the call was dropped
					string drop = to_string(now) + "|call|drop|" + to_string(sessionid);
					int commandfd = userUtils->userFd(user, COMMAND);
					SSL *cmdSsl = clientssl[commandfd];
					write2Client(drop, cmdSsl, iterationKey);
					userUtils->insertLog(Log(TAG_MEDIACALL, drop, user, OUTBOUNDLOG, ip, iterationKey));
				}
			}
		}
	}
}


/////////////////////////////////////////////////////////////////////////////////////////////////
// various post init helper functions
/////////////////////////////////////////////////////////////////////////////////////////////////
void setupSslClient(int fd, int fdType, struct sockaddr_in *info, socklen_t clilen, struct timeval *timeout, SSL_CTX *sslcontext, UserUtils *userUtils, uint64_t relatedKey)
{
	string tag = "";
	if(fdType == SOCKCMD)
	{
		tag = TAG_INCOMINGCMD;
	}
	else
	{
		tag = TAG_INCOMINGMEDIA;
	}

	int incoming = accept(fd, (struct sockaddr *)info, &clilen);
	if(incoming < 0)
	{
		string error = "accept system call error";
		userUtils->insertLog(Log(tag, error, SELF, ERRORLOG, DONTKNOW, relatedKey));
		perror(error.c_str());
		return;
	}
	string ip = inet_ntoa(info->sin_addr);

	//if this socket has problems in the future, give it 1sec to get its act together or giveup on that operation
	if(setsockopt(incoming, SOL_SOCKET, SO_RCVTIMEO, (char*)timeout, sizeof(struct timeval)) < 0)
	{
		string error = "cannot set timeout for incoming socket from " + ip;
		userUtils->insertLog(Log(tag, error, SELF, ERRORLOG, ip, relatedKey));
		perror(error.c_str());
		shutdown(incoming, 2);
		close(incoming);
		return;
	}

	//setup ssl connection
	SSL *connssl = SSL_new(sslcontext);
	SSL_set_fd(connssl, incoming);

	//in case something happened before the incoming connection can be made ssl.
	if(SSL_accept(connssl) <= 0)
	{
		string error = "Problem initializing new command tls connection from " + ip;
		userUtils->insertLog(Log(tag, error, SELF, ERRORLOG, ip, relatedKey));
		SSL_shutdown(connssl);
		SSL_free(connssl);
		shutdown(incoming, 2);
		close(incoming);
	}
	else
	{
		//add the new socket descriptor to the client self balancing tree
		string message = "new command socket from " + ip;
		userUtils->insertLog(Log(TAG_INCOMINGCMD, message, SELF, INBOUNDLOG, ip, relatedKey));
		clientssl[incoming] = connssl;
		sdinfo[incoming] = fdType;
		failCount[incoming] = 0;
	}
}

int readSSLSocket(SSL *sdssl, char *buffer, uint64_t iterationKey) //size is the standard buffer size in const.h
{
	//when a client disconnects, for some reason, the socket is marked as having "stuff" on it.
	//however that "stuff" is no good for ssl, so use eventful boolean to indicate if there was
	//any ssl work done for this actively marked socket descriptor. if not, drop the socket.
	bool waiting = true;

	//read from the socket into the buffer
	int bufferRead=0, amountRead=0;
	bzero(buffer, BUFFERSIZE+1);
	do
	{//wait for the input chunk to come in first before doing something
		amountRead = SSL_read(sdssl, buffer, BUFFERSIZE-bufferRead);
		if(amountRead > 0)
		{
			bufferRead = bufferRead + amountRead;
		}
		int sslerr = SSL_get_error(sdssl, amountRead);
		switch (sslerr)
		{
			case SSL_ERROR_NONE:
				waiting = false;
				break;
			//other cases when necessary. right now only no error signals a successful read
		}
	} while(waiting && SSL_pending(sdssl));

	///SSL_read return 0 = dead socket
	if(amountRead == 0)
	{
		string user;
		int sd = SSL_get_fd(sdssl);
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
	return amountRead;
}

//use a vector to prevent reading out of bounds
vector<string> parse(char command[])
{
//timestamp|login|username|passwd
//timestamp|call|otheruser|sessionid
//timestamp|lookup|user|sessionid
//timestamp|reject|user|sessionid
//timestamp|accept|user|sessionid
//timestamp|timeout|user|sessionid
//timestamp|end|user|sessionid

//timestamp|sessionid : for registering media port
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
#ifdef JAVA1BYTE
	try
	{
		string timestamp = result.at(0);
		size_t notjbyte = timestamp.find_first_not_of(JBYTE[0]);
		if(notjbyte != string::npos)
		{
			result.at(0) = timestamp.substr(notjbyte);
		}
	}
	catch (out_of_range &oorange)
	{
		//nothing you can really do if the vector result has nothing. just don't crap out
	}
#endif
	return result;
}

// sd: a client's socket descriptor
// to make things easier, this function will attempt to find both the media and cmd fd
//	for the user to be removed.
void removeClient(int sd)
{
	string uname = userUtils->userFromFd(sd, COMMAND); //make a lucky guess you got the command fd
	int media, cmd;

#ifdef JSTOPMEDIA
	//make the assumption. if it's right remove both. if it's wrong then... it's still right. remove only the media
	cmd = sd;
	media = userUtils->userFd(uname, MEDIA);
#else
	/*
	 * The actual correct method of removing both sockets regardless of what was supplied
	 */
	if(!uname.empty())
	{//lucky guess was right
		cmd = sd;
		media = userUtils->userFd(uname, MEDIA);
	}
	else
	{//lucky guess was wrong. then you got the media fd
		uname = userUtils->userFromFd(sd, MEDIA);
		cmd = userUtils->userFd(uname, COMMAND);
		media = sd;
	}
#endif

#ifdef VERBOSE
	cout << "removing " << uname << "'s socket descriptors (cmd, media): (" << cmd << "," << media << ")\n";
#endif

	//if for weird reasons the user was just a media port with no cmd don't freak out and crash over no command fd
	if(cmd > 4) //0 stdin, 1 stdout, 2 stderr, 3 command receive, 4, media receive
	{
		if(sdinfo.count(cmd) > 0)
		{
			sdinfo.erase(cmd);
		}
		
		if(failCount.count(cmd > 0))
		{
			failCount.erase(cmd);
		}

		if(clientssl.count(cmd) > 0)
		{
			SSL_shutdown(clientssl[cmd]);
			SSL_free(clientssl[cmd]);
			shutdown(cmd, 2);
			close(cmd);
			clientssl.erase(cmd);
		}
	}

	//if the user never got around to registering a media port, then also don't freak out and crash
	if(media > 4)
	{
		if(sdinfo.count(media) > 0)
		{
			sdinfo.erase(media);
		}
		
		if(failCount.count(cmd > 0))
		{
			failCount.erase(cmd);
		}

		if(clientssl.count(media) > 0)
		{
			//make sure nobody in the live thread is looking at this to avoid a
			//	"rug pulled out form under your feet" scenario (race condition) which leads to a segmentation fault
			clientsslMutex.lock();
			SSL_shutdown(clientssl[media]);
			SSL_free(clientssl[media]);
			shutdown(media, 2);
			close(media);
			clientssl.erase(media);
			clientsslMutex.unlock();
		}
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

	int astatus = sdinfo[afd];
	if(!((astatus ==  -bfd) || (astatus == bfd)))
	{//apparently A isn't waiting for a call with B to start
#ifdef VERBOSE
		cout << prefix << persona << " isn't expecting a call from or in a call with " << personb;
#endif
		return false;
	}

	int bstatus = sdinfo[bfd];
	if(!((bstatus == -afd) || (bstatus == afd)))
	{//apparently B isn't waiting for a call with A to start
#ifdef VERBOSE
		cout << prefix << personb << " isn't expecting a call from or in a call with" << persona;
#endif
		return false;
	}

	//A and B both have a mediafds and are both mutually waiting for a call to start between them
#ifdef VERBOSE
	cout << prefix << "is a real call\n";
#endif
	return true;	
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
