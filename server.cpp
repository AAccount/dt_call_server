#include "server.hpp"

//associates socket descriptors to their ssl structs
std::unordered_map<int, SSL*>clientssl;

//media port for the udp thread
int mediaPort = DEFAULTMEDIA;

//list of who is a live call with whom
std::unordered_map<std::string, std::string> liveList;

UserUtils *userUtils = UserUtils::getInstance();

int main(int argc, char *argv[])
{
	std::string start = (std::string)"starting call operator V" +(std::string)VERSION;
	userUtils->insertLog(Log(TAG_INIT, start, SELF, SYSTEMLOG, SELFIP));

	int cmdFD, cmdPort = DEFAULTCMD; //command port stuff

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
	struct timeval readTimeout;
	readTimeout.tv_sec = 0;
	readTimeout.tv_usec = READTIMEOUT;

	//helper to setup the sockets
	struct sockaddr_in serv_cmd;
	setupListeningSocket(SOCK_STREAM, &readTimeout, &cmdFD, &serv_cmd, cmdPort, userUtils);

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
		userUtils->insertLog(Log(TAG_INIT, "cannot generate private key object", SELF, SYSTEMLOG, SELFIP));
		exit(1);
	}
	fclose(privateKeyFilefopen);
	pthread_t callThread;
	pthread_create(&callThread, NULL, udpThread, (void*)privateKey);

	while(true) //forever
	{
#ifdef VERBOSE
		std::cout << "------------------------------------------\n----------------------------------------\n";
#endif
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(cmdFD, &readfds);
		int maxsd = cmdFD;

		//build the fd watch list consisting of command, and NON live media fds
		for(auto it = clientssl.begin(); it != clientssl.end(); ++it)
		{
			int sd = it->first;
			FD_SET(sd, &readfds);
			maxsd = (sd > maxsd) ? sd : maxsd;
		}

		//wait for somebody to send something to the server
		int sockets = select(maxsd+1, &readfds, NULL, NULL, NULL);
		if(sockets < 0)
		{
			std::string error = "read fds select system call error";
			userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP));
			perror(error.c_str());
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
				std::string error = "accept system call error";
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, DONTKNOW));
				perror(error.c_str());
				continue;
			}
			std::string ip = inet_ntoa(cli_addr.sin_addr);

			//if this socket has problems in the future, give it 1sec to get its act together or giveup on that operation
			if(setsockopt(incomingCmd, SOL_SOCKET, SO_RCVTIMEO, (char*) &readTimeout, sizeof(readTimeout)) < 0)
			{
				std::string error = "cannot set timeout for incoming media socket from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip));
				perror(error.c_str());
				shutdown(incomingCmd, 2);
				close(incomingCmd);
				continue;
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
				std::string error = "Problem initializing new command tls connection (err: " +  std::to_string(sslerr) +") from " + ip;
				userUtils->insertLog(Log(TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip));
				SSL_shutdown(connssl);
				SSL_free(connssl);
				shutdown(incomingCmd, 2);
				close(incomingCmd);
			}
		}

		std::vector<int> removals;

		//check for data on an existing connection
		for(auto it = clientssl.begin(); it != clientssl.end(); ++it)
		{ //figure out if it's a command, or voice data. handle appropriately

			//get the socket descriptor and associated ssl struct from the iterator round
			int sd=it->first;
			SSL *sdssl=it->second;
			if(FD_ISSET(sd, &readfds))
			{
#ifdef VERBOSE
				std::cout << "socket descriptor: " << sd << " was marked as set\n";
#endif

				//read the socket and make sure it wasn't just a socket death notice
				char inputBuffer[COMMANDSIZE + 1];
				int amountRead=readSSL(sdssl, inputBuffer);
				if(amountRead == 0)
				{
					removals.push_back(sd);
					continue;
				}

				//what was previously a workaround now has an official purpose: heartbeat/ping ignore byte
				//this byte is just sent to keep the socket and its various nat tables it takes to get here alive
				std::string  bufferString(inputBuffer);
				if(bufferString == JBYTE)
				{
#ifdef VERBOSE
					std::cout << "Got a " << JBYTE << " cap for media sd " << sd << "\n";
#endif
					continue;
				}
				std::string originalBufferCmd = std::string(inputBuffer); //save original command string before it gets mutilated by strtok
				std::vector<std::string> commandContents = parse(inputBuffer);
				std::string ip=ipFromFd(sd);
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
						std::string ip=ipFromFd(sd);
						userUtils->insertLog(Log(TAG_LOGIN, originalBufferCmd, username, INBOUNDLOG, ip));

						//don't immediately remove old command and media fd. this would allow anyone
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
						int encLength=RSA_public_encrypt(challenge.length(), (const unsigned char*) challenge.c_str(), enc, publicKey, RSA_PKCS1_PADDING);
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
						std::string ip=ipFromFd(sd);
						userUtils->insertLog(Log(TAG_LOGIN, originalBufferCmd, username, INBOUNDLOG, ip));
						std::string triedChallenge=commandContents.at(3);

						//check the challenge
						//	an obvious loophole: send "" as the challenge since that's the default value
						//	DON'T accept the default ""
						std::string answer=userUtils->getChallenge(username);
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
							//don't erase the session in here otherwise the old media fd won't be findable
							//	and its resources leaked
						}

						//dissociate old fd from user otherwise the person will have 2 commandfds listed in
						//	comamandfdMap. remove client will see the old fd pointing to the user and will clear
						//	the user's session key and fds. don't want them cleared as they're now the new ones.
						//	immediately clean up this person's records before all the new stuff goes in
						userUtils->clearSession(username);
						if(liveList.count(username) > 0)
						{
							std::string other=liveList[username];
							liveList.erase(username);
							liveList.erase(other);
						}

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
						if(zapperCmdFd == 0)
						{
							std::string na = std::to_string(now) + "|end|" + zapper;
							write2Client(na, sdssl);
							userUtils->insertLog(Log(TAG_CALL, na, touma, OUTBOUNDLOG, ip));
							continue; //nothing more to do
						}

						//make sure zapper isn't already in a call or waiting for one to connect
						if(liveList.count(zapper) > 0) //won't be in the live list if you're not making a call
						{
							std::string busy=std::to_string(now) + "|end|" + zapper;
							write2Client(busy, sdssl);
							userUtils->insertLog(Log(TAG_CALL, busy, touma, OUTBOUNDLOG, ip));
							continue; //not really invalid either but can't continue any further at this point
						}

						//make sure touma didn't accidentally dial himself
						if(touma == zapper)
						{
							std::string busy=std::to_string(now) + "|end|" + zapper; //ye olde landline did this
							write2Client(busy, sdssl);
							busy="(self dialed) " + busy;
							userUtils->insertLog(Log(TAG_CALL, busy, touma, OUTBOUNDLOG, ip));
							continue; //not really invalid either but can't continue any further at this point
						}

						//setup the media fd statuses
						userUtils->setUserState(zapper, INIT);
						userUtils->setUserState(touma, INIT);
						liveList[zapper]=touma;
						liveList[touma]=zapper;

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
						userUtils->insertLog(Log(TAG_PASSTHROUGH, originalBufferCmd, user, INBOUNDLOG, ip));

						if(!isRealCall(touma, zapper, TAG_PASSTHROUGH))
						{
							continue;
						}

						int zapperfd = userUtils->getCommandFd(zapper);
						SSL *zapperssl = clientssl[zapperfd];
						std::string direct = std::to_string(now) + "|direct|" + aes + "|" + touma;//as in "directly" from touma, not from the server
						write2Client(direct, zapperssl);
						userUtils->insertLog(Log(TAG_PASSTHROUGH, direct, zapper, OUTBOUNDLOG, ipFromFd(zapperfd)));

					}
					else if(command == "ready")
					{//timestamp|ready|touma|zapperkey
						std::string zapper = user;
						std::string touma = commandContents.at(2);
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
						liveList.erase(touma);
						liveList.erase(zapper);

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
	RSA *privateKey = (RSA*)ptr;

	int mediaFd;
	struct sockaddr_in mediaInfo;
	setupListeningSocket(SOCK_DGRAM, NULL, &mediaFd, &mediaInfo, mediaPort, userUtils);

	while(true)
	{
		unsigned char mediaBuffer[BUFFERSIZE+1];
		memset(mediaBuffer, 0, BUFFERSIZE+1);
		struct sockaddr_in sender;
		socklen_t senderLength = sizeof(sender);

		int receivedLength = recvfrom(mediaFd, mediaBuffer, BUFFERSIZE, 0, (struct sockaddr*)&sender, &senderLength);
		if(receivedLength < 0)
		{
			userUtils->insertLog(Log(TAG_UDPTHREAD, "udp read error", SELF, SYSTEMLOG, SELFIP));
			perror("udp thread");
		}

		//quick representation of ip:port that is 32 and 64 bit friendly: glue address and port together
		//	to make the string address_port. doesn't matter it's in network byte order instead of host order.
		//	what matters is consistency (always network order in this case). consistently wrong is consistently right
		std::string summary = std::to_string(sender.sin_addr.s_addr) + std::to_string(sender.sin_port);
		std::string user = userUtils->userFromUdpSummary(summary);

		//either a new media port is being registered or a registered or, need to resend an ack on existing non-live one
		if((user == "") || (userUtils->getUserState(user) != INCALL))
		{//need to send an ack whether it's for the first time or because the first one went missing

			if(receivedLength > 256)//registration is really 10+1+59 = 70 chars which is pkcs1 padded to 256
			{
				//probably garbage or left over voice data from 3G/LTE from an old call
				continue;
			}

			//decrypt media port register command
			unsigned char *dec = (unsigned char*)malloc(RSA_size(privateKey));
			memset(dec, 0, RSA_size(privateKey));
			int decLength = RSA_private_decrypt(receivedLength, mediaBuffer, dec, privateKey, RSA_PKCS1_PADDING);
			if(decLength < 0)
			{
				ERR_print_errors_fp(stderr);
				free(dec);
				continue;
			}
			std::string decryptedCommand(reinterpret_cast<const char *>(dec), decLength);
			free(dec);
			char decryptedArray[decLength+1];
			strcpy(decryptedArray, decryptedCommand.c_str());

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
					//TODO: log
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
				if(liveList.count(user) == 0)
				{
					//TODO: log unnecessary registering
					userUtils->clearUdpInfo(user);
					continue;
				}

				//create and encrypt ack
				std::string ack = std::to_string(now) + "|ok";
				RSA* userKey = userUtils->getPublicKey(user);
				unsigned char* ackEnc = (unsigned char*)malloc(RSA_size(userKey));
				int encLength = RSA_public_encrypt(ack.length(), (const unsigned char*)ack.c_str(), ackEnc, userKey, RSA_PKCS1_PADDING);
				unsigned char ackEncTrimmed[encLength];
				memcpy(ackEncTrimmed, ackEnc, encLength);
				free(ackEnc);

				//send udp ack: no time like the present to test the 2 way udp connection
				int sent = sendto(mediaFd, ackEncTrimmed, encLength, 0, (struct sockaddr*)&sender, senderLength);
				if(sent < 0)
				{
					//TODO: log udp send fail
				}
			}
			catch(std::invalid_argument &badarg)
			{ //timestamp couldn't be parsed. assume someone is trying something fishy
				std::cout << "invalid argument\n";
			}
			catch(std::out_of_range &exrange)
			{ //command was not in the expected format
				std::cout << "out of range exception\n";
			}

		}
		else //implied user != "" and user state == INCALL
		{//in call, passthrough audio untouched (end to end encryption if only to avoid touching more openssl apis)
			struct sockaddr_in otherPerson = userUtils->getUdpInfo(liveList[user]);
			int sent = sendto(mediaFd, mediaBuffer, receivedLength, 0, (struct sockaddr*)&otherPerson, sizeof(otherPerson));
			if(sent < 0)
			{
				//TODO: log udp send fail
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
	if(liveList.count(uname) > 0)
	{
		std::string other=liveList[uname];
		liveList.erase(uname);
		liveList.erase(other);
	}
	userUtils->clearSession(uname);
}

//before doing an accept, reject, end command check to see if it's for a real call
//	or someone trying to get smart with the server
bool isRealCall(std::string persona, std::string personb, std::string tag)
{
	bool real = true;

	if((liveList.count(persona) == 0) || (liveList.count(personb) == 0))
	{
		real = false;
	}

	if((liveList[persona] != personb) || (liveList[personb] != persona))
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
		std::string error = "ssl_write returned an error of: " + std::to_string(errValue);
		userUtils->insertLog(Log(TAG_SSL, error, user, ERRORLOG, ip));
	}
}

std::string ipFromFd(int sd)
{
	struct sockaddr_in thisfd;
	socklen_t thisfdSize = sizeof(struct sockaddr_in);
	getpeername(sd, (struct sockaddr*) &thisfd, &thisfdSize);
	return std::string(inet_ntoa(thisfd.sin_addr));
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






