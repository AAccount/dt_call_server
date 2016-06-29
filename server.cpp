#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include "pgutils.hpp"

#include <iostream>
#include <string>
#include <unordered_map> //hash table
#include <map> //self balancing tree used as a table
#include <vector>

using namespace std;

//using goto in general to avoid excessive indentation and else statements

//information on what each socket descriptor is (command, media) and what it's supposed to be doing if it's a media socket
unordered_map<int, int> sdinfo; 
//associates socket descriptors to their ssl structs
map<int, SSL*>clientssl;
//fail counts of each socket descriptor. if there are too many fails then remove the socket.
//most likely to be used by media sockets during calls. media socket gets reset after a call anyways
//so any fails are going to come from the current call
unordered_map<int, int> failCount;
volatile bool alarmKilled = false;

int main(int argc, char *argv[])
{
	cout << "Call Operator\n";
#ifdef JSTOPMEDIA
	cout << "JSTOPMEDIA ifdef activated\n";
#endif
	//you MUST establish the postgres utilities instance variable here or get a segmentation inside on c->prepare
	PGUtils *postgres = PGUtils::getInstance();
	
	int cmdFD, incomingCmd, cmdPort; //command port stuff
	int mediaFD, incomingMedia, mediaPort, mediaRead; //media port stuff
	int returnValue; //error handling
	int maxsd, sd; //select related vars
	SSL *sdssl; //used for iterating through the ordered map
	socklen_t clilen;

	char bufferCmd[MAXCMD+1];
	char bufferMedia[MAXMEDIA+1];

#ifdef MEMCHECK
	int suicideSocket;
#endif
	
	struct sockaddr_in serv_cmd, serv_media, cli_addr;
	fd_set readfds;
	fd_set writefds;

	if (argc < 3)
	{
		cout << "Must provide command AND media port\n";
		exit(1);
	}

	//openssl setup
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	//set ssl properties
	SSL_CTX *sslcontext = SSL_CTX_new(TLSv1_method());
	if(&sslcontext <= 0)
	{
		perror("ssl initialization problem");
		return 1;
	}
	//TODO: check how ideal const char *ciphers is
	//https://github.com/deadtrickster/cl-dropbox/blob/master/src/ssl.lisp
	const char *ciphers = "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA";
	SSL_CTX_set_cipher_list(sslcontext, ciphers);
	SSL_CTX_set_options(sslcontext, SSL_OP_NO_TLSv1);
	SSL_CTX_set_options(sslcontext, SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_options(sslcontext, SSL_OP_SINGLE_DH_USE);
	returnValue= SSL_CTX_use_PrivateKey_file(sslcontext, "/home/Daniel/Documents/untitled_folder/private.pem", SSL_FILETYPE_PEM);
	if(returnValue <= 0)
	{
		perror("cannot access private key");
		return 1;
	}
	returnValue = SSL_CTX_use_certificate_file(sslcontext, "/home/Daniel/Documents/untitled_folder/public.pem", SSL_FILETYPE_PEM);
	if(returnValue <= 0)
	{
		perror("cannot access public key");
		return 1;
	}

	//socket read timeout option
	struct timeval timeout;
	timeout.tv_sec = SOCKETTIMEOUT;
	timeout.tv_usec = 0;

	//setup command port to accept new connections
	cmdFD = socket(AF_INET, SOCK_STREAM, 0); //tcp socket
	if(cmdFD < 0)
	{
		perror("cannot establish command socket");
		return 1;
	}
	bzero((char *) &serv_cmd, sizeof(serv_cmd));
	cmdPort = atoi(argv[1]);
	serv_cmd.sin_family = AF_INET;
	serv_cmd.sin_addr.s_addr = INADDR_ANY; //listen on any nic
	serv_cmd.sin_port = htons(cmdPort);
	returnValue = bind(cmdFD, (struct sockaddr *) &serv_cmd, sizeof(serv_cmd)); //bind socket to nic and port
	if(returnValue < 0)
	{
		perror("cannot bind command socket to a nic");
		return 1;
	}
	returnValue = setsockopt(cmdFD, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	if(returnValue < 0)
	{
		perror("cannot set command socket options");
		return 1;
	}
	listen(cmdFD, MAXLISTENWAIT);

	//setup media port to accept new connections
	mediaFD = socket(AF_INET, SOCK_STREAM, 0); //tcp socket
	if(mediaFD < 0)
	{
		perror("cannot establish media socket");
		return 1;
	}
	bzero((char *) &serv_media, sizeof(serv_media));
	mediaPort = atoi(argv[2]);
	serv_media.sin_family = AF_INET;
	serv_media.sin_addr.s_addr = INADDR_ANY; //listen on any nic
	serv_media.sin_port = htons(mediaPort);
	returnValue = bind(mediaFD, (struct sockaddr *) &serv_media, sizeof(serv_media)); //bind socket to nic and port
	if(returnValue < 0)
	{
		perror("cannot bind media socket to a nic");
		return 1;
	}
	returnValue = setsockopt(mediaFD, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	if(returnValue < 0)
	{
		perror("cannot set media socket options");
		return 1;
	}
	listen(mediaFD, MAXLISTENWAIT);

	clilen = sizeof(cli_addr);

	//sigpipe is thrown for closing the broken connection. it's gonna happen for a voip server handling mobile clients
	//what're you gonna do about it... IGNORE IT!!
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, alarm_handler);

	//write select timeout
	struct timeval writeTimeout;
	writeTimeout.tv_sec = 0;
	writeTimeout.tv_usec = WSELECTTIMEOUT;


	while(true) //forever
	{
		cout << "------------------------------------------\n----------------------------------------\n";
		FD_ZERO(&readfds);
		FD_SET(cmdFD, &readfds);
		FD_SET(mediaFD, &readfds);
		FD_ZERO(&writefds);
		maxsd = (cmdFD > mediaFD) ? cmdFD : mediaFD; //quick 1 liner for determining the bigger sd

		//http://www.cplusplus.com/reference/map/map/begin/
		map<int, SSL*>::iterator it;
		for(it = clientssl.begin(); it != clientssl.end(); ++it)
		{
			sd = it->first;			
			FD_SET(sd, &readfds);
			FD_SET(sd, &writefds);
			if(sd > maxsd)
			{
				maxsd = sd;
			}
		}

		//wait for somebody to send something to the server
		returnValue = select(maxsd+1, &readfds, NULL, NULL, NULL);
		if(returnValue < 0)
		{
			perror("select system call error");
			return 1;
		}
		cout << "select has " << returnValue << " sockets ready for reading\n";
		
		//now that someone has sent something, check all the sockets to see which ones are writable
		//give a 0.1second time to check. don't want the request to involve an unwritable socket and
		//stall the whole server
		returnValue = select(maxsd+1, NULL, &writefds, NULL, &writeTimeout);
		if(returnValue < 0)
		{
			perror("select system call error");
			return 1;
		}
		cout << "select has " << returnValue << " sockets ready for writing\n";

		//check for a new incoming connection on command port
		if(FD_ISSET(cmdFD, &readfds))
		{
			incomingCmd = accept(cmdFD, (struct sockaddr *) &cli_addr, &clilen);
			if(incomingCmd < 0)
			{
				perror("accept system call error for command");
				goto skipNewCmd;
			}

			//https://tls.mbed.org/discussions/bug-report-issues/ssl_write-and-ssl_read-timeout
			//if this socket has problems in the future, give it 1sec to get its act together or giveup on that operation
			returnValue = setsockopt(incomingCmd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
			if(returnValue < 0)
			{
				perror("cannot set timeout for incoming command socket");
				goto skipNewCmd;
			}

			//setup ssl connection
			SSL *connssl = SSL_new(sslcontext);
			SSL_set_fd(connssl, incomingCmd);
			returnValue = SSL_accept(connssl);

			//in case something happened before the incoming connection can be made ssl.
			if(returnValue <= 0)
			{
				cout << "Problem initializing new command tls connection.\n";
				SSL_shutdown(connssl);
				SSL_free(connssl);
				shutdown(incomingCmd, 2);
				close(incomingCmd);
			}
			else
			{
				//add the new socket descriptor to the client self balancing tree
				cout << "new socket descriptor of " << incomingCmd << " from " << inet_ntoa(cli_addr.sin_addr) << "\n";
				clientssl[incomingCmd] = connssl;
				sdinfo[incomingCmd] = SOCKCMD;
				failCount[incomingCmd] = 0;
			}
		}
		skipNewCmd:;

		//check for a new incoming connection on media port
		if(FD_ISSET(mediaFD, &readfds))
		{
			incomingMedia = accept(mediaFD, (struct sockaddr *) &cli_addr, &clilen);
			if(incomingMedia < 0)
			{
				perror("accept system call error for media");
				goto skipNewMedia;
			}

			//if this socket has problems in the future, give it 1sec to get its act together or giveup on that operation
			returnValue = setsockopt(incomingMedia, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
			if(returnValue < 0)
			{
				perror("cannot set timeout for incoming media socket");
				goto skipNewMedia;
			}

			//setup ssl connection
			SSL *connssl = SSL_new(sslcontext);
			SSL_set_fd(connssl, incomingMedia);
			returnValue = SSL_accept(connssl);

			//in case something happened before the incoming connection can be made ssl
			if(returnValue <= 0)
			{
				cout << "Problem initializing new media tls connection.\n";
				SSL_shutdown(connssl);
				SSL_free(connssl);
				shutdown(incomingMedia, 2);
				close(incomingMedia);
			}
			else
			{
				cout << "new socket descriptor of " << incomingMedia << " from " << inet_ntoa(cli_addr.sin_addr) << "\n";
				clientssl[incomingMedia] = connssl;
				sdinfo[incomingMedia] = SOCKMEDIANEW;
				failCount[incomingMedia] = 0;
			}
		}
		skipNewMedia:;

		//check for data on an existing connection
		//reuse the same iterator variable (reinitialize it too)
		vector<int> removals;
		for(it = clientssl.begin(); it != clientssl.end(); ++it)
		{//figure out if it's a command, or voice data. handle appropirately

			//get the socket descriptor and associated ssl struct from the iterator round
			sd = it->first;
			sdssl = it->second;
			if(FD_ISSET(sd, &readfds))
			{
				cout << "socket descriptor: " << sd << " was marked as set\n";

				//when a client disconnects, for some reason, the socket is marked as having "stuff" on it.
				//however that "stuff" is no good for ssl, so use eventful boolean to indicate if there was
				//any ssl work done for this actively marked socket descriptor. if not, drop the socket.
				bool waiting = true, eventful=false;
				bool isCmdSocket = (sdinfo[sd] == SOCKCMD);

				//read into the appropriate buffer
				if(isCmdSocket)
				{
					bzero(bufferCmd, MAXCMD+1);
					alarm(ALARMTIMEOUT);
					do
					{//wait for the entire ssl record to come in first before doing something

						returnValue = SSL_read(sdssl, bufferCmd, MAXCMD);
						int sslerr = SSL_get_error(sdssl, returnValue);
						switch (sslerr)
						{
							case SSL_ERROR_NONE:
								waiting = false;
								eventful = true; //an ssl operation completed this round, something did happen
								break;
							//other cases when necessary. right now only no error signals a successful read
						}
					} while(waiting && SSL_pending(sdssl));
					alarm(0);
					if(alarmKilled)
					{
						alarmKilled = false;
						cout << "Alarm timeout killed SSL read of command socket\n";
					}
				}
				else
				{
					mediaRead = 0; //to know how much media is ACTUALLY received. don't always assume MAXMEDIA amount was received

					bzero(bufferMedia, MAXMEDIA+1);
					alarm(ALARMTIMEOUT);
					do
					{//wait for the media chunk to come in first before doing something
						returnValue = SSL_read(sdssl, bufferMedia, MAXMEDIA-mediaRead);
						if(returnValue > 0)
						{
							mediaRead = mediaRead + returnValue;
						}
						int sslerr = SSL_get_error(sdssl, returnValue);
						switch (sslerr)
						{
							case SSL_ERROR_NONE:
								waiting = false;
								eventful = true; //an ssl operation completed this round, something did happen
								break;
							//other cases when necessary. right now only no error signals a successful read
						}
					} while(waiting && SSL_pending(sdssl));
					alarm(0);
					if(alarmKilled)
					{
						alarmKilled = false;
						cout << "Alarm killed SSL read of media socket\n";
					}
				}

				//check whether this flagged socket descriptor was of any use this round. if not it's dead
				if(!eventful)
				{
					cout << "socket " << sd << " is dead. remove it\n";
					removals.push_back(sd);
					goto skipfd;
				}

				int sdstate = sdinfo[sd];
				if(sdstate == SOCKCMD)
				{
					cout << "command raw from " << sd << ": " << bufferCmd << "\n";
#ifdef JAVA1BYTE
					//workaround for jclient sending first byte of a command separately
					//after the initial login
					string bufferString(bufferCmd);
					if(bufferString == JBYTE)
					{
						cout << "Got a " << JBYTE << " cap for media sd " << sd << "\n";
						goto skipfd;
					}
#endif
					vector<string> commandContents = parse(bufferCmd);
					try
					{
						string command = commandContents.at(1);
						long now = time(NULL);
						long timestamp = stol(commandContents.at(0)); //catch is for this
						long fivemins = 60*5;
						long timeDifference = abs(now - timestamp);
						if(timeDifference > fivemins)
						{
							//only bother processing the command if the timestamp was valid
							//timestamp was outside +-5mins window of error. disconnect on assumption of replay
							long mins = timeDifference/60;
							long seconds = timeDifference - mins*60;
							cout << "timestamp " << mins << ":" << seconds << " outside 5min window of error\n";
							string invalid = to_string(now) + "|resp|invalid|command\n";
							write2Client(invalid, sdssl);
							goto invalidcmd;
						}

						if(command == "login") //you can do string comparison like this in c++
						{//timestamp|login|username|passwd
							string username = commandContents.at(2);
							string plaintext = commandContents.at(3);
							cout << "attempting login of " << username << " : " << plaintext << "\n";

							int oldcmd = postgres->userFd(username, COMMAND);
							if(oldcmd > 4)
							{//remove old SSL structs to prevent memory leak
								cout << "previous command socket/SSL* exists, will remove\n";
								removals.push_back(oldcmd);
							}

							int oldmedia = postgres->userFd(username, MEDIA);
							if(oldmedia > 4)
							{//remove old SSL structs to prevent memory leak
								cout << "previous meida socket/SSL* exists, will remove\n";
								removals.push_back(oldmedia);
							}

							long sessionid = postgres->authenticate(username, plaintext);
							if(sessionid < 0)
							{//incorrect login credentials. give no hints, just disconnect
								cout << "bad login, error code: " << sessionid << "\n";
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl);
								goto invalidcmd;
							}

							postgres->setFd(sessionid, sd, COMMAND);
							string resp = to_string(now) + "|resp|login|" + to_string(sessionid) + "\n";
							write2Client(resp, sdssl);
							cout << "sending server response: " << resp;
						}

						//variables written from touma calling zapper perspective
						//command will come from touma's cmd fd
						else if (command == "call")
						{//timestamp|call|zapper|toumaid

							long sessionid = stol(commandContents.at(3));
							string zapper = commandContents.at(2);
							string touma = postgres->userFromSessionid(sessionid);
							if(!postgres->verifySessionid(sessionid, sd))
							{
								cout << touma << " has an INVALID SESSION ID. refusing to start call\n";
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl);
								goto invalidcmd;
							}

							cout << "attempting to start call from " << touma << " to " << zapper << "\n";

							//double check touma has a mediafd
							int toumaMediaFd = postgres->userFd(touma, MEDIA);
							if(toumaMediaFd < 0)
							{
								cout << touma << " is trying to make a call without a media fd??\n";
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl);
								goto invalidcmd;
							}

							//find out if zapper is online
							int zapperMediaFd = postgres->userFd(zapper, MEDIA);
							if(zapperMediaFd < 0)
							{
								string na = to_string(now) + "|ring|notavailable|" + zapper + "\n";
								write2Client(na, sdssl);
								cout << zapper << " not online: " << na;
								goto invalidcmd; //while not really an invalid command, there's no point of continuing
							}

							//make sure zapper isn't already in a call
							int currentState = sdinfo[zapperMediaFd];
							if(currentState != SOCKMEDIAIDLE)
							{
								string busy = to_string(now) + "|ring|busy|" + zapper + "\n";
								write2Client(busy, sdssl);
								cout << zapper << " is in a call: " << busy;
								goto invalidcmd; //not really invalid either but can't continue any further at this point
							}


							//make sure touma didn't accidentally dial himself
							if(touma == zapper)
							{
								string busy = to_string(now) + "|ring|busy|" + zapper + "\n"; //ye olde landline did this
								write2Client(busy, sdssl);
								cout << touma << ", you can't call yourself: " << busy;
								goto invalidcmd; //not really invalid either but can't continue any further at this point
							}

							//setup the media fd statuses
							sdinfo[zapperMediaFd] = INITWAITING + toumaMediaFd;
							sdinfo[toumaMediaFd] = INITWAITING + zapperMediaFd;

							//tell touma that zapper is being rung
							string notifyTouma = to_string(now) + "|ring|available|" + zapper + "\n";
							write2Client(notifyTouma, sdssl);
							cout << zapper << " is online, initiate a call: " << notifyTouma;
			
							//tell zapper touma wants to call her
							string notifyZapper = to_string(now) + "|ring|incoming|" + touma + "\n";
							int zapperCmdFd = postgres->userFd(zapper, COMMAND);
							SSL *zapperssl = clientssl[zapperCmdFd];
							write2Client(notifyZapper, zapperssl);
							cout << "notifying " << zapper << " of incoming call: " << notifyZapper;							
						}
						else if (command == "lookup")
						{
							string who = commandContents.at(2);
							long sessionid = stol(commandContents.at(3));
							if(!postgres->verifySessionid(sessionid, sd))
							{
								cout << "invalid sessionid attempting to do a user lookup\n";
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl);
								goto invalidcmd;
							}
							string exists = (postgres->doesUserExist(who)) ? "exists" : "doesntexist";
							string resp = to_string(now) + "|lookup|" + who + "|" + exists + "\n";
							write2Client(resp, sdssl);
							cout << "lookup of " << who << ": " << resp;
						}

						//variables written when zapper accepets touma's call
						//command will come from zapper's cmd fd
						else if (command == "accept")
						{//timestamp|accept|touma|zapperid
							long sessionid = stol(commandContents.at(3));
							string zapper = postgres->userFromSessionid(sessionid);
							string touma = commandContents.at(2);
							if(!isRealCall(zapper, touma))
							{
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl);
								goto invalidcmd;
							}

							cout << zapper << " accepts " << touma << "'s call\n";
							int zapperMediaFd = postgres->userFd(zapper, MEDIA);
							int toumaMediaFd = postgres->userFd(touma, MEDIA);
							sdinfo[zapperMediaFd] = toumaMediaFd;
							sdinfo[toumaMediaFd] = zapperMediaFd;

							//tell touma zapper accepted his call request										
							//	AND confirm to touma, it's zapper he's being connected with
							int toumaCmdFd = postgres->userFd(touma, COMMAND);
							SSL *toumaCmdSsl = clientssl[toumaCmdFd];
							string toumaResp = to_string(now) + "|call|start|" + zapper + "\n";
							write2Client(toumaResp, toumaCmdSsl);
							cout << touma << "'s device to start the call session: " << toumaResp;

							//confirm to zapper she's being connected to touma
							string zapperResp = to_string(now) + "|call|start|" + touma + "\n";
							write2Client(zapperResp, sdssl);
							cout << zapper << "'s device to start the call session: " << zapperResp;
						}

						//variables modeled after setup touma calling zapper for easier readability
						//reject command would come from zapper's cmd fd
						else if (command == "reject")
						{//timestamp|reject|touma|sessionid
							long sessionid = stol(commandContents.at(3));
							string zapper = postgres->userFromSessionid(sessionid);
							string touma = commandContents.at(2);

							if(!isRealCall(zapper, touma))
							{
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl);
								goto invalidcmd;
							}

							//set touma's and zapper's media socket state back to idle
							int toumaMediaFd = postgres->userFd(touma, MEDIA);
							int zapperMediaFd = postgres->userFd(zapper, MEDIA);
							sdinfo[toumaMediaFd] = SOCKMEDIAIDLE;
							sdinfo[zapperMediaFd] = SOCKMEDIAIDLE;

							//tell touma his call was rejected
							int toumaCmdFd = postgres->userFd(touma, COMMAND);
							SSL *toumaCmdSsl = clientssl[toumaCmdFd];
							string resp = to_string(now) + "|call|reject|" + zapper + "\n";
							write2Client(resp, toumaCmdSsl);
							cout << zapper << " rejects " << touma << "'s call: " << resp;
						}

						//variables modled after setup touma calling zapper for easier readability
						//end could come from either of them
						else if (command == "end")
						{
							//timestamp|end|touma|zappersid : zapper wants to end the call with touma
							//timestamp|end|zapper|toumasid : touma wants to end the call with zapper

							long sessionid = stol(commandContents.at(3));
							string wants2End = postgres->userFromSessionid(sessionid);
							string stillTalking = commandContents.at(2);

							if(!isRealCall(wants2End, stillTalking))
							{
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl);
								goto invalidcmd;
							}

							//set touma's and zapper's media socket state back to idle
							int endMediaFd = postgres->userFd(wants2End, MEDIA);
							int talkingMediaFd = postgres->userFd(stillTalking, MEDIA);
							sdinfo[endMediaFd] = SOCKMEDIAIDLE;
							sdinfo[talkingMediaFd] = SOCKMEDIAIDLE;

							//tell the one still talking, it's time to hang up
							string resp = to_string(now) + "|call|end|" + wants2End + "\n";
							int talkingCmdFd = postgres->userFd(stillTalking, COMMAND);
							SSL *talkingCmdSsl = clientssl[talkingCmdFd];
							write2Client(resp, talkingCmdSsl);
							cout << wants2End << " terminating call with " << stillTalking << ": " << resp;
						}
#ifdef MEMCHECK
						//used to test memory leaks. stop the server and valgrind check it
						//the last 2 strings in the 4 string command structure timestamp|command|arg1|arg2 (arg1, arg2) can be anything
						else if(command == "suicide")
						{
							cout << "Shutting down call operator\n";
							suicideSocket = sd;
							if(clientssl.size() > 2)
							{
								cout << "WARNING: more than 1 client connected. May have false positive memory leak";
							}
							goto breakout;
						}
#endif
						//call timeout: zapper hasn't answer touma's call request in the 1 minute ring time
						//cancel the call
						//nothing has to be sent to touma because his phone will automatically take care of itself
						//	to back back to the home screen
						else if(command =="timeout")
						{
							string zapper = commandContents.at(2);
							long sessionid = stol(commandContents.at(3));
							string touma = postgres->userFromSessionid(sessionid);
							cout << zapper << " has taken over a minute to answer " << touma << "'s call. timeout\n";

							if(!isRealCall(touma, zapper))
							{
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl);
								goto invalidcmd;
							}

							//set touma's and zapper's media socket state back to idle
							int toumaMediaFd = postgres->userFd(touma, MEDIA);
							int zapperMediaFd = postgres->userFd(zapper, MEDIA);
							sdinfo[toumaMediaFd] = SOCKMEDIAIDLE;
							sdinfo[zapperMediaFd] = SOCKMEDIAIDLE;

							//tell zapper that time's up for answering touma's call
							string resp = to_string(now) + "|ring|timeout|" + touma;
							int zapperCmdFd = postgres->userFd(zapper, COMMAND);
							SSL *zapperCmdSsl = clientssl[zapperCmdFd];
							write2Client(resp, zapperCmdSsl);
							cout << "sending timeout to " << zapper << ": " << resp << "\n";
						}
						else //commandContents[1] is not a known command... something fishy???
						{
							string unknown = commandContents.at(1);
							cout << "unknown command of: " << unknown << "\n";
						}
					}
					catch(invalid_argument &badarg)
					{//timestamp couldn't be parsed. assume someone is trying something fishy
						cout << "can't get timestamp from command: " << badarg.what() << "\n";
						long now = time(NULL);
						string invalid = to_string(now) + "|resp|invalid|command\n";
						write2Client(invalid, sdssl);
					}
					catch(out_of_range &exrange)
					{
						cout << "client sent a misformed command\n";
						long now = time(NULL);
						string invalid = to_string(now) + "|resp|invalid|command\n";
						write2Client(invalid, sdssl);
					}
					invalidcmd:; //bad timestamp, invalid sessionid, not real call... etc.
				}
				else if(sdstate == SOCKMEDIANEW)
				{//timestamp|sessionid (of the user this media fd should be registered/associated to)

					cout << "going to try and associate new media socket with an existing client\n";

#ifdef JAVA1BYTE
					//workaround for jclient sending first byte of a command separately
					//after the intial login
					string bufferString(bufferMedia);
					if(bufferString == JBYTE)
					{
						cout << "Got a " << JBYTE << " cap for media sd " << sd << "\n";
						goto skipfd;
					}
#endif
					vector<string> commandContents = parse(bufferMedia);
					try
					{
						//check timestamp is ok
						long now = time(NULL);
						long timestamp = stol(commandContents.at(0));
						long fivemins = 60*5;
						long timeDifference = abs(now - timestamp);
						if(timeDifference > fivemins)
						{
							long mins = timeDifference/60;
							long seconds = timeDifference - mins*60;
							cout << "timestamp " << mins << ":" << seconds << " outside 5min window of error\n";
							goto skipreg;
						}

						//check sessionid belongs to a signed in user
						long sessionid = stol(commandContents.at(1));
						string intendedUser = postgres->userFromSessionid(sessionid);
						if(intendedUser == "")
						{
							cout << "erroneous sessionid sent... brute force???\n";
							goto skipreg;
						}
						cout << "According to the session id, the media socket is for: " << intendedUser << "\n";

						//get the user's command fd to do an ip lookup of which ip the command fd is associated with
						int cmdfd = postgres->userFd(intendedUser, COMMAND);
						if(cmdfd < 0)
						{//with a valid timestamp, valid sessionid, there is no cmd fd for this user??? how??? you must log in through a cmd fd to get a sessionid
							cout << "SOMETHING IS WRONG!!! valid timestamp and sessionid but " << intendedUser << " has no command fd\n";
							goto skipreg;
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

						cout << intendedUser << " last registered from ip address: " << inet_ntoa(cmdFdInfo.sin_addr) << "\n";
						cout << intendedUser << " is CURRENTLY registering from ip address: " << inet_ntoa(thisfd.sin_addr) << "\n";

						if(thisfdip != cmdip)
						{//valid timestamp, valid sessionid, sessionid has command fd... but the media port association came from a different ip than the command fd...??? HOW??? all requests come from a cell phone app with 1 ip...
							cout << "SOMETHING IS REALLY WRONG. with a valid timestamp, sessionid, and a command fd associated with the sessionid, the request to associate the media fd is coming from another ip???\n";
							goto skipreg;
						}
						postgres->setFd(sessionid, sd, MEDIA);
						sdinfo[sd] = SOCKMEDIAIDLE;

					}
					catch(invalid_argument &badarg)
					{
						cout << "can't get timestamp when trying establish which client a media socket should go to\n";
					}
					catch(out_of_range &exrange)
					{
						cout << "client sent a misformed media port association request\n";
					}

					skipreg:; //skip media fd registration. something didn't check out ok.
				}
				else if(sdstate == SOCKMEDIAIDLE || sdstate > 100)
				{
					if(sdstate == SOCKMEDIAIDLE)
					{
						cout << "received data on an established media socket. ignore it\n";
#ifdef JCALLDIAG
						cout << "Got : " << bufferMedia << "\n";
#endif
					}
					else //if(sdstate > 100)
					{
						cout << "received data on a media socket waiting for a call accept\n";
#ifdef JCALLDIAG
						cout << "Got : " << bufferMedia << "\n";
#endif
					}
				}
				else if(sdstate > 0) //in call
				{
					//when in call your sdstate is the media socket descriptor of the person you're calling
#ifdef JCALLDIAG
					cout << "received " << mediaRead << " bytes of call data: " << bufferMedia << "\n";
#endif
					if(clientssl.count(sdstate) > 0) //the other person's media sd does exist
					{
						if(FD_ISSET(sdstate, &writefds))
						{//only send if the socket's buffer has place
							SSL *recepient = clientssl[sdstate];
							SSL_write(recepient, bufferMedia, mediaRead);
						}
						else
						{//if there is no place, just drop the 32bytes of voice
						 //a backlog of voice will cause a call lag. better to ask again and say "didn't catch that"
							cout << "sending to socket " << sdstate << " failed because it is busy\n";
							int fails = failCount[sdstate]++;
							failCount[sdstate] = fails++;
							if(fails > FAILMAX)
							{
								cout << "too many fails. removing this socket";
								removeClient(sdstate);
								//on the next round if(clientssl.count(sdstate)) will fail and go to
								//the else which will send the call drop. waiting for the next round to
								//avoid copying and pasting identical code
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
						//because the record has been removed, you can't do postgres->userFromFd(zapper_mediafd_state, MEDIA)
						//to find out she's in a call with touma. 
						//therefore you have to send a different command... the call drop command

						//reset the media connection state
						string user = postgres->userFromFd(sd, MEDIA);
						sdinfo[sd] = SOCKMEDIAIDLE;

						//drop the call for the user
						long now = time(NULL);
						long sessionid = postgres->userSessionId(user);
						if(sessionid < 0)
						{
							cout << "How?? " << user << "'s call was dropped but " << user << " had no sessionid to begin with\n";
							goto skipfd;
						}
						string drop = to_string(now) + "|call|drop|" + to_string(sessionid) + "\n";

						//write to the person who got dropped's command fd that the call was dropped
						int commandfd = postgres->userFd(user, COMMAND);
						SSL *cmdSsl = clientssl[commandfd];
						write2Client(drop, cmdSsl);
						cout << user << "'s call was dropped: " << drop;
					}
				}

			}// if FD_ISSET : figure out command or voice and handle appropriately
		skipfd:; //fd was dead. removed it. go on to the next one
		}// for loop going through the fd set

		//now that all fds are finished inspecting, remove any of them that are dead.
		//don't mess with the map contents while the iterator is live.
		//removing while runnning causes segfaults because if the removed item gets iterated over after removal
		//it's no longer there so you get a segfault
		if(removals.size() > 0)
		{
			cout << "Removing " << removals.size() << " dead/leftover sockets\n";
			vector<int>::iterator rmit;
			for(rmit = removals.begin(); rmit != removals.end(); ++rmit)
			{
				int kickout = *rmit;
				if(clientssl.count(kickout) > 0)
				{
					cout << "Removing " << kickout << "\n";
					removeClient(kickout);
				}
			}
			removals.clear();
		}
		cout << "_____________________________________\n_________________________________\n";
	}

#ifdef MEMCHECK
	breakout:;
	removeClient(suicideSocket);

	//normally these can't be de-malloced because they're always needed.
	//	de-malloc them so that only true, preventable memory leaks are reported

	//stop postgres
	PGUtils *instance = PGUtils::getInstance();
	instance->killInstance();

	//openssl stuff
	SSL_CTX_free(sslcontext);
	ERR_free_strings();
	EVP_cleanup();
	
	//close ports
	close(cmdFD);
	close(mediaFD);
#endif
	return 0; 
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
	return result;
}

// sd: a client's socket descriptor
// to make things eaiser, this function will attempt to find both the media and cmd fd
//	for the user to be removed.
void removeClient(int sd)
{
	PGUtils *postgres = PGUtils::getInstance();
	string uname = postgres->userFromFd(sd, COMMAND); //make a lucky guess you got the command fd
	int media, cmd;

#ifdef JSTOPMEDIA
	//make the assumption. if it's right remove both. if it's wrong then... it's still right. remove only the media
	cmd = sd;
	media = postgres->userFd(uname, MEDIA);
#else
	/*
	 * The actual correct method of removing both sockets regardless of what was supplied
	 */
	if(uname != "ENOUSER")
	{//lucky guess was right
		cmd = sd;
		media = postgres->userFd(uname, MEDIA);
	}
	else
	{//lucky guess was wrong. then you got the media fd
		uname = postgres->userFromFd(sd, MEDIA);
		cmd = postgres->userFd(uname, COMMAND);
		media = sd;
	}
#endif

	cout << "removing " << uname << "'s socket descriptors (cmd, media): (" << cmd << "," << media << ")\n";

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
			SSL_shutdown(clientssl[media]);
			SSL_free(clientssl[media]);
			shutdown(media, 2);
			close(media);
			clientssl.erase(media);
		}
	}

	//incase of crash, there will be no entires in the hash table and tree. skip these pairs and just flush out
	//	the irrelevant db info
	postgres->clearSession(uname);
}

//before doing an accept, reject, end command check to see if it's for a real call
//	or someone trying to get smart with the server
bool isRealCall(string persona, string personb)
{
	PGUtils *postgres = PGUtils::getInstance();
	string prefix =  "call between " + persona + " && " + personb + ": ";

	//check if A and B even have media FDs
	int afd = postgres->userFd(persona, MEDIA);
	int bfd = postgres->userFd(personb, MEDIA);
	if(afd < 0)
	{
		cout << prefix << persona << " doesn't even have a media fd\n";
		return false;
	}
	if(bfd < 0)
	{
		cout << prefix << personb << " doesn't even have a media fd\n";
		return false;
	}

	int astatus = sdinfo[afd];
	if(!((astatus == INITWAITING + bfd) || (astatus == bfd)))
	{//apparently A isn't waiting for a call with B to start
		cout << prefix << persona << " isn't expecting a call from or in a call with " << personb;
		return false;
	}

	int bstatus = sdinfo[bfd];
	if(!((bstatus == INITWAITING + afd) || (bstatus == afd)))
	{//apparently B isn't waiting for a call with A to start
		cout << prefix << personb << " isn't expecting a call from or in a call with" << persona;
		return false;
	}

	//A and B both have a mediafds and are both mutually waiting for a call to start between them
	cout << prefix << "is a real call\n";
	return true;	
}


// write a message to a client
void write2Client(string response, SSL *respSsl)
{
	int length = response.size();
	char serverOut[length+1]; //make sure the amount written out represents the response string and isn't response + tons of 0 padding
	bzero(serverOut, length+1);
	memcpy(serverOut, response.c_str(), length);

	int retries = 10;
	bool finished = false;
	do
	{
		int errValue = SSL_write(respSsl, serverOut, length);
		if(errValue > 0)
		{
			finished = true;
		}
		else if(errValue == SSL_ERROR_WANT_WRITE)
		{
			retries--;
		}
	} while(retries > 0 && !finished);

	if(!finished)
	{
		PGUtils *postgres = PGUtils::getInstance();
		int socket = SSL_get_fd(respSsl);
		string didntReceive = postgres->userFromFd(socket, COMMAND);
		cout << "Couldn't send command to: " << didntReceive << "\n";
	}
}

void alarm_handler(int signum)
{
	alarmKilled = true;
}


