#include "server.hpp"

//associates socket descriptors to their ssl structs
std::unordered_map<int, SSL*>clientssl;

UserUtils *userUtils = UserUtils::getInstance();

int main(int argc, char *argv[])
{
	std::string start = (std::string)"starting call operator V" +(std::string)VERSION;
	userUtils->insertLog(Log(TAG_INIT, start, SELF, SYSTEMLOG, SELFIP));

	int cmdFD, cmdPort = DEFAULTCMD; //command port stuff
	int mediaPort = DEFAULTMEDIA;

	std::string publicKeyFile;
	std::string privateKeyFile;
	std::string ciphers = DEFAULTCIPHERS;
	std::string dhfile = "";

	//use a helper function to read the config file
	readServerConfig(&cmdPort, &mediaPort, &publicKeyFile, &privateKeyFile, &ciphers, &dhfile, userUtils);

	//helper to setup the ssl context
	SSL_CTX *sslcontext = setupOpenSSL(ciphers, privateKeyFile, publicKeyFile, dhfile, userUtils);
	if(sslcontext == NULL)
	{
		userUtils->insertLog(Log(TAG_INIT, "could not establish ssl context", SELF, SYSTEMLOG, SELFIP));
		exit(1);
	}

	//socket read timeout option
	struct timeval unauthTimeout; //for new sockets
	unauthTimeout.tv_sec = 0;
	unauthTimeout.tv_usec = UNAUTHTIMEOUT;

	//helper to setup the sockets
	struct sockaddr_in serv_cmd;
	setupListeningSocket(SOCK_STREAM, &unauthTimeout, &cmdFD, &serv_cmd, cmdPort, userUtils);

	//sigpipe is thrown for closing the broken connection. it's gonna happen for a voip server handling mobile clients
	//what're you gonna do about it... IGNORE IT!!
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	//get the stuff needed to start the udp media thread and then start it
	FILE *privateKeyFilefopen = fopen(privateKeyFile.c_str(), "r");
	RSA *privateKey = PEM_read_RSAPrivateKey(privateKeyFilefopen, NULL, NULL, NULL);
	if(privateKey == NULL)
	{
		std::string error = "cannot generate private key object " + std::string(ERR_error_string(ERR_get_error(), NULL));
		userUtils->insertLog(Log(TAG_INIT, error, SELF, SYSTEMLOG, SELFIP));
		exit(1);
	}
	fclose(privateKeyFilefopen);

	//package the stuff to start the udp thread and start it
	struct UdpArgs *args = (struct UdpArgs*)malloc(sizeof(struct UdpArgs));
	args->port = mediaPort;
	args->privateKey = privateKey;
	pthread_t callThread;
	if(pthread_create(&callThread, NULL, udpThread, args) != 0)
	{
		std::string error = "cannot create the udp thread (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP));
		exit(1); //with no udp thread the server cannot handle any calls
	}
	pthread_setname_np(callThread, "VoUDP"); //not fatal if the name is too long

	while(true) //forever
	{
#ifdef VERBOSE
		std::cout << "------------------------------------------\n----------------------------------------\n";
#endif
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(cmdFD, &readfds);
		int maxsd = cmdFD;

		//build the fd watch list of command fds
		for(auto sslMapping : clientssl)
		{
			int sd = sslMapping.first;
			FD_SET(sd, &readfds);
			maxsd = (sd > maxsd) ? sd : maxsd;
		}

		//wait for somebody to send something to the server
		int sockets = select(maxsd+1, &readfds, NULL, NULL, NULL);
		if(sockets < 0)
		{
			std::string error = "read fds select system call error (" + std::to_string(errno) + ") " + std::string(strerror(errno));
			userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP));
			exit(1); //see call thread fx for why
		}
#ifdef VERBOSE
		std::cout << "select has " << sockets << " sockets ready for reading\n";
#endif

		//check for a new incoming connection on command port
		if(FD_ISSET(cmdFD, &readfds))
		{
			struct sockaddr_in cli_addr;
			socklen_t clilen = sizeof(cli_addr);

			int incomingCmd = accept(cmdFD, (struct sockaddr *) &cli_addr, &clilen);
			if(incomingCmd < 0)
			{
				std::string error = "accept system call error (" + std::to_string(errno) + ") " + std::string(strerror(errno));
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, DONTKNOW));
				continue;
			}
			std::string ip = inet_ntoa(cli_addr.sin_addr);

			//for new sockets that nobody owns, don't give much leniency for timeouts
			if(setsockopt(incomingCmd, SOL_SOCKET, SO_RCVTIMEO, (char*) &unauthTimeout, sizeof(unauthTimeout)) < 0)
			{
				std::string error = "cannot set timeout for incoming command socket (" + std::to_string(errno) + ") " + std::string(strerror(errno));
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip));
				shutdown(incomingCmd, 2);
				close(incomingCmd);
				continue;
			}

			//disable nagle delay for heartbeat which is a 1 char payload
			int nagle = 0;
			if(setsockopt(incomingCmd, IPPROTO_TCP, TCP_NODELAY, (char*)&nagle, sizeof(int)))
			{
				std::string error = "cannot disable nagle delay (" + std::to_string(errno) + ") " + std::string(strerror(errno));
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip));
			}

			//setup ssl connection
			SSL *connssl = SSL_new(sslcontext);
			SSL_set_fd(connssl, incomingCmd);

			//give 10 tries to get an ssl connection because first try isn't always successful
			int sslerr = SSL_ERROR_NONE;
			bool proceed = false;
			int retries = DT_SSL_ACCEPT_RETRIES;
			while(retries > 0)
			{
				int result = SSL_accept(connssl);
				sslerr = SSL_get_error(connssl, result);
				if(sslerr == SSL_ERROR_NONE) //everything ok, proceed
				{
					proceed = true;
					break;
				}
				else if (sslerr == SSL_ERROR_WANT_READ)
				{//incomplete handshake, try again
					retries--;
				}
				else
				{//some other error. stop
					break;
				}
			}

			if(proceed)
			{
				std::string message = "new command socket from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGCMD, message, SELF, INBOUNDLOG, ip));
				clientssl[incomingCmd] = connssl;
			}
			else
			{
				std::string error = "Problem initializing new command tls connection" + std::string(ERR_error_string(ERR_get_error(), NULL));
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip));
				SSL_shutdown(connssl);
				SSL_free(connssl);
				shutdown(incomingCmd, 2);
				close(incomingCmd);
			}
		}

		std::vector<int> removals;

		//check for new commands
		for(auto sslMapping : clientssl)
		{

			//get the socket descriptor and associated ssl struct from the iterator round
			int sd = sslMapping.first;
			SSL *sdssl = sslMapping.second;
			if(FD_ISSET(sd, &readfds))
			{
#ifdef VERBOSE
				std::cout << "socket descriptor: " << sd << " was marked as set\n";
#endif

				//read the socket and make sure it wasn't just a socket death notice
				char inputBuffer[COMMANDSIZE + 1];
				int amountRead = readSSL(sdssl, inputBuffer);
				if(amountRead == 0)
				{
					removals.push_back(sd);
					continue;
				}

				//check if the bytes sent are valid ascii like c#
				if (!legitimateAscii(inputBuffer, amountRead))
				{
					std::string unexpected = "unexpected byte in string";
					std::string user = userUtils->userFromCommandFd(sd);
					std::string ip = ipFromFd(sd);
					userUtils->insertLog(Log(TAG_BADCMD, unexpected, user, ERRORLOG, ip));
					continue;
				}

				//what was previously a workaround now has an official purpose: heartbeat/ping ignore byte
				//this byte is just sent to keep the socket and its various nat tables it takes to get here alive
				std::string  bufferString(inputBuffer);
				if(bufferString == JBYTE)
				{
#ifdef VERBOSE
					std::cout << "Got a heartbeat byte on " << sd << "\n";
#endif
					continue;
				}
				std::string originalBufferCmd = std::string(inputBuffer); //save original command string before it gets mutilated by strtok
				std::vector<std::string> commandContents = parse(inputBuffer);
				std::string ip = ipFromFd(sd);
				time_t now=time(NULL);

				try
				{
					std::string command = commandContents.at(1);
					uint64_t timestamp=(uint64_t) std::stoull(commandContents.at(0)); //catch is for this
					uint64_t maxError=60 * MARGIN_OF_ERROR;
					uint64_t timeDifference= std::max((uint64_t) now, timestamp) - std::min((uint64_t) now, timestamp);
					if(timeDifference > maxError)
					{
						//only bother processing the command if the timestamp was valid

						//prepare the error log
						uint64_t mins=timeDifference / 60;
						uint64_t seconds=timeDifference - mins * 60;
						std::string error="command received was outside the " + std::to_string(MARGIN_OF_ERROR) + " minute margin of error: " + std::to_string(mins) + "mins, " + std::to_string(seconds) + "seconds";
						error=error + " (" + originalBufferCmd + ")";
						std::string user=userUtils->userFromCommandFd(sd);
						userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip));

						//send the rejection to the client
						std::string invalid=std::to_string(now) + "|invalid";
						write2Client(invalid, sdssl);
						continue;
					}

					if(command == "login1") //you can do string comparison like this in c++
					{ //timestamp|login1|username
						std::string username=commandContents.at(2);
						userUtils->insertLog(Log(TAG_LOGIN, originalBufferCmd, username, INBOUNDLOG, ip));

						//don't immediately remove old command fd. this would allow anyone
						//	to send a login1 command and kick out a legitimately logged in person.

						//get the user's public key
						RSA *publicKey=userUtils->getPublicKey(username);
						if(publicKey == NULL)
						{
							//not a real user. send login rejection
							std::string invalid=std::to_string(now) + "|invalid";
							userUtils->insertLog(Log(TAG_LOGIN, invalid, username, OUTBOUNDLOG, ip));
							write2Client(invalid, sdssl);
							removals.push_back(sd); //nothing useful can come from this socket
							continue;
						}

						//generate the challenge gibberish
						std::string challenge=Utils::randomString(CHALLENGE_LENGTH);
#ifdef VERBOSE
						std::cout << "challenge: " << challenge << "\n";
#endif
						userUtils->setChallenge(username, challenge);
						unsigned char* enc=(unsigned char*) malloc(RSA_size(publicKey));
						int encLength=RSA_public_encrypt(challenge.length(), (const unsigned char*)challenge.c_str(), enc, publicKey, RSA_PKCS1_OAEP_PADDING);
						std::string encString=stringify(enc, encLength);
						free(enc);

						//send the challenge
						std::string resp=std::to_string(now) + "|login1resp|" + encString;
						write2Client(resp, sdssl);
						userUtils->insertLog(Log(TAG_LOGIN, resp, username, OUTBOUNDLOG, ip));
						continue; //login command, no session key to verify, continue to the next fd after proccessing login1
					}
					else if(command == "login2")
					{ //timestamp|login2|username|challenge

						//ok to store challenge answer in the log. challenge is single use, disposable
						std::string username=commandContents.at(2);
						userUtils->insertLog(Log(TAG_LOGIN, originalBufferCmd, username, INBOUNDLOG, ip));
						std::string triedChallenge=commandContents.at(3);

						//check the challenge
						//	an obvious loophole: send "" as the challenge since that's the default value
						//	DON'T accept the default ""
						std::string answer = userUtils->getChallenge(username);
#ifdef VERBOSE
						std::cout << "@username: " << username << " answer: " << answer << " attempt: " << triedChallenge << "\n";
#endif
						if(answer == "" || triedChallenge != answer) //no challenge registered for this person or wrong answer
						{
							//person doesn't have a challenge to answer or isn't supposed to be
							std::string invalid=std::to_string(now) + "|invalid";
							userUtils->insertLog(Log(TAG_LOGIN, invalid, username, OUTBOUNDLOG, ip));
							write2Client(invalid, sdssl);
							removals.push_back(sd); //nothing useful can come from this socket

							//reset challenge in case it was wrong
							userUtils->setChallenge(username, "");
							continue;
						}

						//for authenticated connections, allow more timeout in case of bad internet
						struct timeval authTimeout;
						authTimeout.tv_sec = AUTHTIMEOUT;
						authTimeout.tv_usec = 0;
						if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&authTimeout, sizeof(authTimeout)) < 0)
						{
							std::string error = "cannot set timeout for authenticated command socket (" + std::to_string(errno) + ") " + std::string(strerror(errno));
							userUtils->insertLog(Log(TAG_LOGIN, error, SELF, ERRORLOG, ip));
						}

						//now that the person has successfully logged in, remove the old information.
						//	this person has established new connections so it's 100% sure the old ones aren't
						//	needed anymore.
						int oldcmd=userUtils->getCommandFd(username);
						if(oldcmd > 0)
						{							//remove old SSL structs to prevent memory leak
#ifdef VERBOSE
						std::cout << "previous command socket/SSL* exists, will remove\n";
#endif
							removals.push_back(oldcmd);
						}

						//dissociate old fd from user otherwise the person will have 2 commandfds listed in
						//	comamandfdMap. remove client will see the old fd pointing to the user and will clear
						//	the user's session key and fds. don't want them cleared as they're now the new ones.
						//	immediately clean up this person's records before all the new stuff goes in
						userUtils->clearSession(username);

						//challenge was correct and wasn't "", set the info
						std::string sessionkey=Utils::randomString(SESSION_KEY_LENGTH);
						userUtils->setSessionKey(username, sessionkey);
						userUtils->setCommandFd(sessionkey, sd);
						userUtils->setChallenge(username, ""); //reset after successful completion

						//send an ok
						std::string resp=std::to_string(now) + "|login2resp|" + sessionkey;
						write2Client(resp, sdssl);
#ifndef VERBOSE
						resp=std::to_string(now) + "|login2resp|" + SESSION_KEY_PLACEHOLDER;
#endif
						userUtils->insertLog(Log(TAG_LOGIN, resp, username, OUTBOUNDLOG, ip));
						continue; //login command, no session key to verify, continue to the next fd after proccessing login2
					}

					//done processing login commands.
					//all (non login) commands have the format timestamp|COMMAND|(stuff)...sessionkey
					std::string sessionkey = commandContents.at(commandContents.size()-1);
					std::string user=userUtils->userFromCommandFd(sd);
#ifndef VERBOSE //unless needed, don't log session keys as they're still in use
					originalBufferCmd.replace(originalBufferCmd.find(sessionkey), SESSION_KEY_LENGTH, SESSION_KEY_PLACEHOLDER);
#endif
					if(!userUtils->verifySessionKey(sessionkey, sd))
					{
						std::string error="INVALID SESSION ID. refusing command (" + originalBufferCmd + ")";
						userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip));

						std::string invalid=std::to_string(now) + "|invalid";
						write2Client(invalid, sdssl);
						userUtils->insertLog(Log(TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip));
						continue;
					}

					//variables written from touma calling zapper perspective
					//command will come from touma's cmd fd
					if(command == "call")
					{//timestamp|call|zapper|toumakey

						std::string zapper=commandContents.at(2);
						std::string touma=user;
						userUtils->insertLog(Log(TAG_CALL, originalBufferCmd, touma, INBOUNDLOG, ip));
						int zapperCmdFd = userUtils->getCommandFd(zapper);

						//find out if zapper has a command fd (signed in)
						bool offline = (zapperCmdFd == 0);
						//make sure zapper isn't already in a call or waiting for one to connect
						bool busy = (userUtils->getCallWith(zapper) != "");
						//make sure touma didn't accidentally dial himself
						bool selfDial = (touma == zapper);

						if(offline || busy || selfDial)
						{
							std::string na = std::to_string(now) + "|end|" + zapper;
							write2Client(na, sdssl);
							userUtils->insertLog(Log(TAG_CALL, na, touma, OUTBOUNDLOG, ip));
							continue; //nothing more to do
						}

						//setup the user statuses and register the call with user utils
						userUtils->setUserState(zapper, INIT);
						userUtils->setUserState(touma, INIT);
						userUtils->setCallPair(touma, zapper);

						//tell touma that zapper is being rung
						std::string notifyTouma = std::to_string(now) + "|available|" + zapper;
						write2Client(notifyTouma, sdssl);
						userUtils->insertLog(Log(TAG_CALL, notifyTouma, touma, OUTBOUNDLOG, ip));

						//tell zapper touma wants to call her
						std::string notifyZapper = std::to_string(now) + "|incoming|" + touma;
						SSL *zapperssl=clientssl[zapperCmdFd];
						write2Client(notifyZapper, zapperssl);
						std::string zapperip = ipFromFd(zapperCmdFd);
						userUtils->insertLog(Log(TAG_CALL, notifyZapper, zapper, OUTBOUNDLOG, ip));
					}
					//variables written when zapper accepets touma's call
					//command will come from zapper's cmd fd
					else if(command == "accept")
					{//timestamp|accept|touma|zapperkey
						std::string zapper=user;
						std::string touma=commandContents.at(2);
						userUtils->insertLog(Log(TAG_ACCEPT, originalBufferCmd, zapper, INBOUNDLOG, ip));

						if(!isRealCall(zapper, touma, TAG_ACCEPT))
						{
							continue;
						}

						//arbitrarily chosen that the one who makes the call (touma) gets to generate the aes key
						int toumaCmdFd=userUtils->getCommandFd(touma);
						SSL *toumaCmdSsl=clientssl[toumaCmdFd];
						std::string toumaResp=std::to_string(now) + "|prepare|" + userUtils->getPublicKeyDump(zapper) + "|"  + zapper;
						write2Client(toumaResp, toumaCmdSsl);
						userUtils->insertLog(Log(TAG_ACCEPT, toumaResp, touma, OUTBOUNDLOG, ipFromFd(toumaCmdFd)));

						std::string zapperResp=std::to_string(now) + "|prepare|" + touma;
						write2Client(zapperResp, sdssl);
						userUtils->insertLog(Log(TAG_ACCEPT, zapperResp, zapper, OUTBOUNDLOG, ip));
					}
					else if(command == "passthrough")
					{//timestamp|passthrough|zapper|encrypted aes key|toumakey
						std::string zapper = commandContents.at(2);
						std::string touma = user;
						std::string aes = commandContents.at(3);
						originalBufferCmd.replace(originalBufferCmd.find(aes), aes.length(), AES_PLACEHOLDER);
						userUtils->insertLog(Log(TAG_PASSTHROUGH, originalBufferCmd, user, INBOUNDLOG, ip));

						if(!isRealCall(touma, zapper, TAG_PASSTHROUGH))
						{
							continue;
						}

						int zapperfd = userUtils->getCommandFd(zapper);
						SSL *zapperssl = clientssl[zapperfd];
						std::string direct = std::to_string(now) + "|direct|" + aes + "|" + touma;//as in "directly" from touma, not from the server
						write2Client(direct, zapperssl);
						direct.replace(direct.find(aes), aes.length(), AES_PLACEHOLDER);
						userUtils->insertLog(Log(TAG_PASSTHROUGH, direct, zapper, OUTBOUNDLOG, ipFromFd(zapperfd)));

					}
					else if(command == "ready")
					{//timestamp|ready|touma|zapperkey
						std::string zapper = user;
						std::string touma = commandContents.at(2);
						userUtils->insertLog(Log(TAG_READY, originalBufferCmd, user, INBOUNDLOG, ip));
						if(!isRealCall(zapper, touma, TAG_READY))
						{
							continue;
						}

						userUtils->setUserState(zapper, INCALL);
						if(userUtils->getUserState(touma) == INCALL)
						{//only if both people are ready can  you start the call

							//tell touma zapper accepted his call request
							//	AND confirm to touma, it's zapper he's being connected with
							int toumaCmdFd = userUtils->getCommandFd(touma);
							SSL *toumaCmdSsl = clientssl[toumaCmdFd];
							std::string toumaResp = std::to_string(now) + "|start|" + zapper;
							write2Client(toumaResp, toumaCmdSsl);
							userUtils->insertLog(Log(TAG_ACCEPT, toumaResp, touma, OUTBOUNDLOG, ipFromFd(toumaCmdFd)));

							//confirm to zapper she's being connected to touma
							std::string zapperResp = std::to_string(now) + "|start|" + touma;
							write2Client(zapperResp, sdssl);
							userUtils->insertLog(Log(TAG_ACCEPT, zapperResp, zapper, OUTBOUNDLOG, ip));
						}
					}
					//whether it's a call end or call timeout or call reject, the result is the same
					else if(command == "end")
					{ //timestamp|end|zapper|toumakey
						std::string zapper=commandContents.at(2);
						std::string touma=user;
						userUtils->insertLog(Log(TAG_END, originalBufferCmd, touma, INBOUNDLOG, ip));

						if(!isRealCall(touma, zapper, TAG_END))
						{
							continue;
						}

						//set touma's and zapper's user state to idle/none
						userUtils->setUserState(touma, NONE);
						userUtils->setUserState(zapper, NONE);
						userUtils->removeCallPair(touma);

						//tell zapper to hang up whether it's a call end or time's up to answer a call
						std::string resp = std::to_string(now) + "|end|" + touma;
						int zapperCmdFd=userUtils->getCommandFd(zapper);
						SSL *zapperCmdSsl=clientssl[zapperCmdFd];
						write2Client(resp, zapperCmdSsl);
						userUtils->insertLog(Log(TAG_END, resp, zapper, OUTBOUNDLOG, ipFromFd(zapperCmdFd)));
					}
					else //commandContents[1] is not a known command... something fishy???
					{
						userUtils->insertLog(Log(TAG_BADCMD, originalBufferCmd, userUtils->userFromCommandFd(sd), INBOUNDLOG, ip));
					}
				}
				catch(std::invalid_argument &badarg)
				{ //timestamp couldn't be parsed. assume someone is trying something fishy
					std::string user=userUtils->userFromCommandFd(sd);
					userUtils->insertLog(Log(TAG_BADCMD, originalBufferCmd, user, INBOUNDLOG, ip));

					std::string error="INVALID ARGUMENT EXCEPTION: (uint64_t)stoull (std::string too long) could not parse timestamp";
					userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip));

					std::string invalid=std::to_string(now) + "|invalid";
					write2Client(invalid, sdssl);
					userUtils->insertLog(Log(TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip));
				}
				catch(std::out_of_range &exrange)
				{
					std::string user=userUtils->userFromCommandFd(sd);
					userUtils->insertLog(Log(TAG_BADCMD, originalBufferCmd, user, INBOUNDLOG, ip));

					std::string error="OUT OF RANGE (vector<string> parsed from command) EXCEPTION: client sent a misformed command";
					userUtils->insertLog(Log(TAG_BADCMD, error, user, ERRORLOG, ip));

					std::string invalid=std::to_string(now) + "|invalid";
					write2Client(invalid, sdssl);
					userUtils->insertLog(Log(TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip));
				}
			} // if FD_ISSET : figure out command or voice and handle appropriately
		}// for loop going through the fd set

		//now that all fds are finished inspecting, remove any of them that are dead.
		//don't mess with the map contents while the iterator is live.
		//removing while runnning causes segfaults because if the removed item gets iterated over after removal
		//it's no longer there so you get a segfault
		if(removals.size() > 0)
		{
#ifdef VERBOSE
			std::cout << "Removing " << removals.size() << " dead/leftover sockets\n";
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
#ifdef VERBOSE
		std::cout << "_____________________________________\n_________________________________\n";
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
	return 0; 
}

void* udpThread(void *ptr)
{
	//unpackage media thread args
	struct UdpArgs *receivedArgs = (struct UdpArgs*)ptr;
	RSA *privateKey = receivedArgs->privateKey;
	int mediaPort = receivedArgs->port;
	free(ptr);

	//establish the udp socket for voice data
	int mediaFd;
	struct sockaddr_in mediaInfo;
	setupListeningSocket(SOCK_DGRAM, NULL, &mediaFd, &mediaInfo, mediaPort, userUtils);

	//make the socket an expidited one
	int express = IPTOS_DSCP_EF;
	if(setsockopt(mediaFd, IPPROTO_IP, IP_TOS, (char*)&express, sizeof(int)) < 0)
	{
		std::string error="cannot set udp socket dscp expedited (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		userUtils->insertLog(Log(TAG_UDPTHREAD, error, SELF, ERRORLOG, SELFIP));
	}

	while(true)
	{
		//setup buffer to receive on udp socket
		unsigned char mediaBuffer[MEDIASIZE+1];
		memset(mediaBuffer, 0, MEDIASIZE+1);
		struct sockaddr_in sender;
		socklen_t senderLength = sizeof(struct sockaddr_in);

		//read encrypted voice data or registration
		int receivedLength = recvfrom(mediaFd, mediaBuffer, MEDIASIZE, 0, (struct sockaddr*)&sender, &senderLength);
		if(receivedLength < 0)
		{
			std::string error = "udp read error with errno " + std::to_string(errno) + ": " + std::string(strerror(errno));
			userUtils->insertLog(Log(TAG_UDPTHREAD, error, SELF, ERRORLOG, SELFIP));
			continue; //received nothing, this round is a write off
		}

		//quick representation of ip:port that is 32 and 64 bit friendly: glue address and port together
		//	to make the string address_port. doesn't matter it's in network byte order instead of host order.
		//	what matters is consistency (always network order in this case). consistently wrong is consistently right
		std::string summary = std::string(inet_ntoa(sender.sin_addr)) + ":" + std::to_string(ntohs(sender.sin_port));
		std::string user = userUtils->userFromUdpSummary(summary);
		ustate state = userUtils->getUserState(user);

		//need to send an ack whether it's for the first time or because the first one went missing.
		if((user == "") || (state  == INIT))
		{
			std::cout << "sending ack for summary: " << summary << " belonging to " << user << "/\n";
			if(receivedLength > RSA_size(privateKey))
			{
				//probably garbage or left over voice data from 3G/LTE from an old call
				std::cout << "received invalid length of " << std::to_string(receivedLength) << "/\n";
				continue;
			}

			std::string ip = std::string(inet_ntoa(sender.sin_addr));

			//decrypt media port register command
			unsigned char *dec = (unsigned char*)malloc(RSA_size(privateKey));
			memset(dec, 0, RSA_size(privateKey));
			int decLength = RSA_private_decrypt(receivedLength, mediaBuffer, dec, privateKey, RSA_PKCS1_OAEP_PADDING);
			if(decLength < 0)
			{
				std::string error = "media port registration error: " + std::string(ERR_error_string(ERR_get_error(), NULL));
				userUtils->insertLog(Log(TAG_UDPTHREAD, error, user, ERRORLOG, ip));
				free(dec);
				continue;
			}
			std::string decryptedCommand(reinterpret_cast<const char *>(dec), decLength);
			free(dec);
			char decryptedArray[decLength+1];
			strncpy(decryptedArray, decryptedCommand.c_str(), decLength);
			decryptedArray[decLength] = 0;

			//check the decrypted contents don't have unwanted junk like c#
			if(!legitimateAscii(decryptedArray, decLength-1))
			{
				std::string unexpected = "unexpected byte in string";
				userUtils->insertLog(Log(TAG_UDPTHREAD, unexpected, user, ERRORLOG, ip));
				continue;
			}

			//try to parse decrypted command
			std::vector<std::string> parsed = parse(decryptedArray);
			try
			{
				//check timestamp
				time_t now = time(NULL);
				uint64_t timestamp = (uint64_t)std::stoull(parsed.at(0)); //catch is for this
				uint64_t maxError=60 * MARGIN_OF_ERROR;
				uint64_t timeDifference = std::max((uint64_t) now, timestamp) - std::min((uint64_t) now, timestamp);
				if(timeDifference > maxError)
				{
					std::string error = "register media port timestamp too far off by " + std::to_string(timeDifference) + " seconds";
					userUtils->insertLog(Log(TAG_UDPTHREAD, error, user, ERRORLOG, ip));
					continue;
				}

				//for first time registering figure out who it is
				if(user == "")
				{
					std::string sessionkey = parsed.at(1);
					userUtils->setUdpSummary(sessionkey, summary);
					userUtils->setUdpInfo(sessionkey, sender);
					user = userUtils->userFromSessionKey(sessionkey);
				}

				//if the person is not in a call, there is no need to register a media port
				if(userUtils->getCallWith(user) == "")
				{
					userUtils->clearUdpInfo(user);
					continue;
				}

				//create and encrypt ack
				std::string ack = std::to_string(now) + "|" + userUtils->getSessionKey(user) + "|ok";
				RSA* userKey = userUtils->getPublicKey(user);
				unsigned char* ackEnc = (unsigned char*)malloc(RSA_size(userKey));
				int encLength = RSA_public_encrypt(ack.length(), (const unsigned char*)ack.c_str(), ackEnc, userKey, RSA_PKCS1_OAEP_PADDING);
				unsigned char ackEncTrimmed[encLength];
				memcpy(ackEncTrimmed, ackEnc, encLength);
				free(ackEnc);

				//send udp ack: no time like the present to test the 2 way udp connection
				int sent = sendto(mediaFd, ackEncTrimmed, encLength, 0, (struct sockaddr*)&sender, senderLength);
				if(sent < 0)
				{
					std::string error = "udp sendto failed during media port registration with errno (" + std::to_string(errno) + ") " + std::string(strerror(errno));
					userUtils->insertLog(Log(TAG_UDPTHREAD, error, user , ERRORLOG, ip));
				}
			}
			catch(std::invalid_argument &badarg)
			{ //timestamp couldn't be parsed. assume someone is trying something fishy
				std::string error = "invalid argument exception, udp thread: " + decryptedCommand;
				userUtils->insertLog(Log(TAG_UDPTHREAD, error, user, ERRORLOG, ip));
			}
			catch(std::out_of_range &exrange)
			{ //command was not in the expected format
				std::string error = "out of range excpetion, udp thread: " + decryptedCommand;
				userUtils->insertLog(Log(TAG_UDPTHREAD, error, user, ERRORLOG, ip));
			}

		}
		else if(state == INCALL)
		{//in call, passthrough audio untouched (end to end encryption if only to avoid touching more openssl apis)
			std::string otherPerson = userUtils->getCallWith(user);

			//if the other person disappears midway through, calling clear session on his socket will cause
			//	you to have nobody listed in User.callWith (or "" default value). getUdpInfo("") won't end well
			if(otherPerson == "")
			{
				continue;
			}

			struct sockaddr_in otherSocket = userUtils->getUdpInfo(otherPerson);
			int sent = sendto(mediaFd, mediaBuffer, receivedLength, 0, (struct sockaddr*)&otherSocket, sizeof(otherSocket));
			if(sent < 0)
			{
				std::string error = "udp sendto failed during live call with errno (" + std::to_string(errno) + ") " + std::string(strerror(errno));
				std::string ip = std::string(inet_ntoa(otherSocket.sin_addr));
				userUtils->insertLog(Log(TAG_UDPTHREAD, error, user , ERRORLOG, ip));
			}
		}
	}
	return NULL;
}


//use a vector to prevent reading out of bounds
std::vector<std::string> parse(char command[])
{
//timestamp|login1|username
//timestamp|login2|username|challenge_decrypted

//session key is always the last one for easy censoring in the logs
//timestamp|call|otheruser|sessionkey
//timestamp|lookup|otheruser|sessionkey
//timestamp|reject|otheruser|sessionkey
//timestamp|accept|otheruser|sessionkey
//timestamp|end|otheruser|sessionkey
//timestamp|passthrough|otheruser|(aes key encrypted)|sessionkey
//timestamp|ready|otheruser|sessionkey

	char *token;
	int i = 0;
	std::vector<std::string> result;
	token = strtok(command, "|");
	while(token != NULL && i < COMMAND_MAX_SEGMENTS)
	{
		result.push_back(std::string(token));
		token = strtok(NULL, "|");
		i++;
	}
	return result;
}

// sd: a client's socket descriptor
void removeClient(int sd)
{
	std::string uname = userUtils->userFromCommandFd(sd);

	SSL_shutdown(clientssl[sd]);
	SSL_free(clientssl[sd]);
	shutdown(sd, 2);
	close(sd);
	clientssl.erase(sd);

	//clean up the live list if needed
	userUtils->clearSession(uname);
}

//before doing an accept, reject, end command check to see if it's for a real call
//	or someone trying to get smart with the server
bool isRealCall(std::string persona, std::string personb, std::string tag)
{
	bool real = true;

	std::string awith = userUtils->getCallWith(persona);
	std::string bwith = userUtils->getCallWith(personb);
	if((awith == "") || (bwith == ""))
	{
		real = false;
	}

	if((persona != bwith) || (personb != awith))
	{
		real = false;
	}

	if(!real)
	{
		int fd = userUtils->getCommandFd(persona);
		std::string ip = ipFromFd(fd);
		std::string error = persona + " sent a command for a nonexistant call";
		userUtils->insertLog(Log(tag, error, persona, ERRORLOG, ip));

		time_t now = time(NULL);
		std::string invalid = std::to_string(now) + "|invalid";
		if(fd > 0)
		{
			SSL *ssl = clientssl[fd];
			write2Client(invalid, ssl);
			userUtils->insertLog(Log(tag, invalid, persona, OUTBOUNDLOG, ip));
		}
	}
	return real;
}


// write a message to a client
void write2Client(std::string response, SSL *respSsl)
{
	int socket = SSL_get_fd(respSsl);
	std::string user = userUtils->userFromCommandFd(socket);
	std::string ip = ipFromFd(socket);

	int errValue = SSL_write(respSsl, response.c_str(), response.size());
	if(errValue <= 0)
	{
		std::string error = "ssl_write returned an error of " + std::string(ERR_error_string(ERR_get_error(), NULL));
		userUtils->insertLog(Log(TAG_SSL, error, user, ERRORLOG, ip));
	}
}

std::string ipFromFd(int sd)
{
	struct sockaddr_in thisfd;
	socklen_t thisfdSize = sizeof(struct sockaddr_in);
	int result = getpeername(sd, (struct sockaddr*) &thisfd, &thisfdSize);
	if(result == 0)
	{
		return std::string(inet_ntoa(thisfd.sin_addr));
	}
	else
	{
		return "(" +std::to_string(errno) + ": " + std::string(strerror(errno)) + ")";
	}
}

std::string stringify(unsigned char *bytes, int length)
{
	std::string result = "";
	for(int i=0; i<length; i++)
	{
		std::string number = std::to_string(bytes[i]);
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

int readSSL(SSL *sdssl, char inputBuffer[])
{
	//read from the socket into the buffer
	int bufferRead=0, totalRead=0;
	bool waiting;
	memset(inputBuffer, 0, COMMANDSIZE+1);
	do
	{//wait for the input chunk to come in first before doing something
		totalRead = SSL_read(sdssl, inputBuffer, COMMANDSIZE-bufferRead);
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
		std::string user = userUtils->userFromCommandFd(sd);
		std::string ip = ipFromFd(sd);
		std::string error = "socket has died";
		userUtils->insertLog(Log(TAG_DEADSOCK, error, user, ERRORLOG, ip));
	}
	return totalRead;
}

bool legitimateAscii(char buffer[], int length)
{
	for (int i = 0; i < length; i++)
	{
		char byte = buffer[i];

		bool isSign = ((byte == 43) || (byte == 45));
		bool isNumber = ((byte >= 48) && (byte <= 57));
		bool isUpperCase = ((byte >= 65) && (byte <= 90));
		bool isLowerCase = ((byte >= 97) && (byte <= 122));
		bool isDelimiter = (byte == 124);

		if (!isSign && !isNumber && !isUpperCase && !isLowerCase && !isDelimiter)
		{//actually only checking for ascii of interest
			return false;
		}
	}
	return true;
}

