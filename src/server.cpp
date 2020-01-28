/*
 * server.cpp
 *
 *  Created on: December 8, 2015
 *      Author: Daniel
 */

#include "server.hpp"

//associates socket descriptors to their ssl structs
std::unordered_map<int, std::unique_ptr<Client>> clients;

int main(int argc, char* argv[])
{
	std::string settingsLocation = "/etc/dtoperator";
	std::string logLocation = "/var/log/dtoperator";
	
	//read command line arguments if they're there
	if(argc == 5)
	{
		const std::string SETTINGS = "--settings";
		const std::string LOG = "--log";
		
		const std::string arg1(argv[1]);
		const std::string value1(argv[2]);
		const std::string arg2(argv[3]);
		const std::string value2(argv[4]);
		
		if(arg1 == SETTINGS)
		{
			settingsLocation = value1;
		}
		if(arg1 == LOG)
		{
			logLocation = value1;
		}
		
		if(arg2 == SETTINGS)
		{
			settingsLocation = value2;
		}
		if(arg2 == LOG)
		{
			logLocation = value2;
		}
	}
	else
	{
		std::cout << "Command line arguments dtoperator --settings /path/to/settings --log /where/logs/go" << "\n";
		std::cout << "Using default values for settings and log location " << settingsLocation << " " << logLocation << "\n";
	}
	
	//initialize the logger first because user utils needs the logger
	Logger::setLogLocation(logLocation);
	Logger* logger = Logger::getInstance();

	//initialize user utils
	UserUtils::setFileLocation(settingsLocation);
	UserUtils* userUtils = UserUtils::getInstance();

	const std::string start = "starting call operator V" + VERSION();
	logger->insertLog(Log(Log::TAG::STARTUP, start, Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()).toString());
	
	//initialize library
	if(sodium_init() < 0)
	{
		logger->insertLog(Log(Log::TAG::STARTUP, "couldn't initialize sodium library", Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()).toString());
		exit(1);
	}

	int cmdPort = DEFAULTCMD; //command port stuff
	int mediaPort = DEFAULTMEDIA;

	std::string sodiumPublic = "";
	std::string sodiumPrivate = "";

	//use a helper function to read the config file
	readServerConfig(settingsLocation, cmdPort, mediaPort, sodiumPublic, sodiumPrivate, logger);

	//socket read timeout option
	struct timeval unauthTimeout; //for new sockets
	unauthTimeout.tv_sec = 0;
	unauthTimeout.tv_usec = UNAUTHTIMEOUT;

	//helper to setup the command socket
	int cmdFD;
	struct sockaddr_in serv_cmd;
	setupListeningSocket(SOCK_STREAM, &unauthTimeout, &cmdFD, &serv_cmd, cmdPort);

	//sigpipe is thrown for closing the broken connection. it's gonna happen for a voip server handling mobile clients
	//what're you gonna do about it... IGNORE IT!!
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	//setup sodium keys
	const std::unique_ptr<unsigned char[]> sodiumPublicKey = std::make_unique<unsigned char[]>(crypto_box_PUBLICKEYBYTES);
	Stringify::destringify(sodiumPublic, sodiumPublicKey.get());
	char* sodiumPublicStringMemory = &sodiumPublic[0];
	randombytes_buf(sodiumPublicStringMemory, sodiumPublic.length());
	const std::unique_ptr<unsigned char[]> sodiumPrivateKey = std::make_unique<unsigned char[]>(crypto_box_SECRETKEYBYTES);
	Stringify::destringify(sodiumPrivate, sodiumPrivateKey.get());
	char* sodiumPrivateStringMemory = &sodiumPrivate[0];
	randombytes_buf(sodiumPrivateStringMemory, sodiumPrivate.length());

	try
	{
		std::thread udpThreadObj(udpThread, mediaPort, std::ref(sodiumPublicKey), std::ref(sodiumPrivateKey));
		udpThreadObj.detach();
	}
	catch(std::system_error& e)
	{
		std::string error = "cannot create the udp thread (" + std::string(e.what()) + ") ";
		logger->insertLog(Log(Log::TAG::STARTUP, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()).toString());
		exit(1); //with no udp thread the server cannot handle any calls
	}

	std::unique_ptr<unsigned char[]> inputBufferArray = std::make_unique<unsigned char[]>(COMMANDSIZE);
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
		for(const auto& clientMapping : clients)
		{
			int sd = clientMapping.first;
			FD_SET(sd, &readfds);
			maxsd = (sd > maxsd) ? sd : maxsd;
		}

		//wait for somebody to send something to the server
		const int sockets = select(maxsd+1, &readfds, NULL, NULL, NULL);
		if(sockets < 0)
		{
			std::string error = "read fds select system call error (" + std::to_string(errno) + ") " + std::string(strerror(errno));
			logger->insertLog(Log(Log::TAG::STARTUP, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()).toString());
			exit(1); //see call thread fx for why
		}
#ifdef VERBOSE
		std::cout << "select has " << sockets << " sockets ready for reading\n";
#endif

		//check for a new incoming connection on command port
		if(FD_ISSET(cmdFD, &readfds))
		{
			socketAccept(cmdFD, &unauthTimeout);
		}

		std::vector<int> removals;

		//check for new commands
		for(const auto& clientTableEntry : clients)
		{

			//get the socket descriptor and associated ssl struct from the iterator round
			if(FD_ISSET(clientTableEntry.first, &readfds))
			{
#ifdef VERBOSE
				std::cout << "socket descriptor: " << sd << " was marked as set\n";
#endif

				//read the socket and make sure it wasn't just a socket death notice
				unsigned char* inputBuffer = inputBufferArray.get();
				memset(inputBuffer, 0, COMMANDSIZE);
				const int amountRead = read(clientTableEntry.first, inputBuffer, COMMANDSIZE);
				if(amountRead < 1)
				{
					removals.push_back(clientTableEntry.first);
					continue;
				}

				//if it is a new/first time client, send the "SSL key"
				/**
				 * This setup should me MitM safe.
				 * Assume: client public key --> middle man catch, send middle man public key --> server
				 * On the server: server sign with server's key encrypt with middle man --> middle man
				 * 	middle man decrypts tcp session key --> can't send to client because he can't sign as the server
				 * Clients are required to have the server's public sodium key ahead of time.
				 */
				if(clientTableEntry.second->isNew())
				{
					const std::string ip = ipFromFd(clientTableEntry.first);
					std::unique_ptr<unsigned char[]> decryptedInputBuffer = std::make_unique<unsigned char[]>(COMMANDSIZE);//need to have space for malicious input that may be as long as the whole buffer
					unsigned char* initialTempPublic = decryptedInputBuffer.get(); //extra space will be zeroed
					int unsealok = crypto_box_seal_open(initialTempPublic, inputBuffer, amountRead, sodiumPublicKey.get(), sodiumPrivateKey.get());
					if(unsealok != 0)
					{
						const std::string error = "bad initial sodium socket setup";
						logger->insertLog(Log(Log::TAG::INCOMINGCMD, error, Log::DONTKNOW() , Log::TYPE::ERROR, ip).toString());
						continue;
					}

					//send the equivalent of the SSL key
					std::unique_ptr<unsigned char[]> encTCPKey = std::make_unique<unsigned char[]>(COMMANDSIZE);
					int encTCPKeyLength = 0;
					SodiumUtils::sodiumEncrypt(true, clientTableEntry.second->getSymmetricKey().get(), crypto_secretbox_KEYBYTES, sodiumPrivateKey.get(), initialTempPublic, encTCPKey, encTCPKeyLength);
					if(encTCPKeyLength > 0)
					{
						const int errValue = write(clientTableEntry.first, encTCPKey.get(), encTCPKeyLength);
						if(errValue == -1)
						{
							const std::string error = "initial sodium socket setup write errno " + std::to_string(errno) + " " + std::string(strerror(errno));
							logger->insertLog(Log(Log::TAG::TCP, error, Log::DONTKNOW(), Log::TYPE::ERROR, ip).toString());
							removals.push_back(clientTableEntry.first);
						}
							clientTableEntry.second->hasBeenSeen();
					}
					else //sodium encrypted command socket failed. the client can try again
					{
						removals.push_back(clientTableEntry.first);
					}

					continue; //sent the initial key. nothing left to do for this client
				}

				//for existing clients, sodium decrypt the command
				int decLength = 0;
				std::unique_ptr<unsigned char[]> decBuffer = std::make_unique<unsigned char[]>(COMMANDSIZE);
				SodiumUtils::sodiumDecrypt(false, inputBuffer, amountRead, clientTableEntry.second->getSymmetricKey().get(), NULL, decBuffer, decLength);
				if(decLength == 0)
				{
					continue; //decryption failed, move on
				}

				//check if the bytes sent are valid ascii like c#
				if (!legitimateAscii(decBuffer.get(), decLength))
				{
					const std::string unexpected = "unexpected byte in string";
					const std::string user = userUtils->userFromCommandFd(clientTableEntry.first);
					const std::string ip = ipFromFd(clientTableEntry.first);
					logger->insertLog(Log(Log::TAG::BADCMD, unexpected, user, Log::TYPE::ERROR, ip).toString());
					continue;
				}

				//what was previously a workaround now has an official purpose: heartbeat/ping ignore byte
				//this byte is just sent to keep the socket and its various nat tables it takes to get here alive
				std::string bufferCmd((char*)decBuffer.get(), decLength);
				if(bufferCmd == JBYTE())
				{
#ifdef VERBOSE
					std::cout << "Got a heartbeat byte on " << sd << "\n";
#endif
					continue;
				}
				std::string originalBufferCmd = bufferCmd; //copy bufferCmd to another string before strtok messes up the original
				const std::vector<std::string> commandContents = parse((unsigned char*)bufferCmd.c_str());
				const std::string ip = ipFromFd(clientTableEntry.first);
				const std::string user=userUtils->userFromCommandFd(clientTableEntry.first);
				const time_t now = time(NULL);

				const int segments = commandContents.size();
				if(segments < COMMAND_MIN_SEGMENTS || segments > COMMAND_MAX_SEGMENTS)
				{
					logger->insertLog(Log(Log::TAG::BADCMD, originalBufferCmd+"\nbad amount of command segments: " + std::to_string(segments), user, Log::TYPE::ERROR, ip).toString());
					continue;
				}

				const bool timestampOK = checkTimestamp((const std::string&)commandContents.at(0), Log::TAG::BADCMD, originalBufferCmd, user, ip);
				if (!timestampOK)
				{
					//checkTimestamp will logg an error
					continue;
				}
				const std::string command = commandContents.at(1);

				if (command == "login1") //you can do string comparison like this in c++
				{ //timestamp|login1|username
					const std::string username = commandContents.at(2);
					logger->insertLog(Log(Log::TAG::LOGIN, originalBufferCmd, username, Log::TYPE::INBOUND, ip).toString());

					//don't immediately remove old command fd. this would allow anyone
					//	to send a login1 command and kick out a legitimately logged in person.

					//get the user's public key
					unsigned char userSodiumPublic[crypto_box_PUBLICKEYBYTES] = {};
					const bool exists = userUtils->getSodiumPublicKey(username, userSodiumPublic);
					if (!exists)
					{
						//not a real user. send login rejection
						const std::string invalid = std::to_string(now) + "|invalid";
						logger->insertLog(Log(Log::TAG::LOGIN, invalid, username, Log::TYPE::OUTBOUND, ip).toString());
						write2Client(invalid, clientTableEntry.first);
						removals.push_back(clientTableEntry.first); //nothing useful can come from this socket
						continue;
					}

					//generate the challenge gibberish
					const std::string challenge = SodiumUtils::randomString(CHALLENGE_LENGTH);
					userUtils->setChallenge(username, challenge);
#ifdef VERBOSE
					std::cout << "challenge: " << challenge << "\n";
#endif
					int encLength = 0;
					std::unique_ptr<unsigned char[]> enc = std::make_unique<unsigned char[]>(COMMANDSIZE);
					SodiumUtils::sodiumEncrypt(true, (unsigned char*) (challenge.c_str()), challenge.length(), sodiumPrivateKey.get(), userSodiumPublic, enc, encLength);
					if (encLength < 1)
					{
						logger->insertLog(Log(Log::TAG::LOGIN, "sodium encryption of the challenge failed", username, Log::TYPE::ERROR, ip).toString());
						continue;
					}
					const std::string encString = Stringify::stringify(enc.get(), encLength);

					//send the challenge
					const std::string resp = std::to_string(now) + "|login1resp|" + encString;
					write2Client(resp, clientTableEntry.first);
					logger->insertLog(Log(Log::TAG::LOGIN, resp, username, Log::TYPE::OUTBOUND, ip).toString());
					continue; //login command, no session key to verify, continue to the next fd after proccessing login1
				}
				else if (command == "login2")
				{ //timestamp|login2|username|challenge|keepudp(optional)

					//ok to store challenge answer in the log. challenge is single use, disposable
					const std::string username = commandContents.at(2);
					logger->insertLog(Log(Log::TAG::LOGIN, originalBufferCmd, username, Log::TYPE::INBOUND, ip).toString());
					const std::string triedChallenge = commandContents.at(3);

					//check the challenge
					//	an obvious loophole: send "" as the challenge since that's the default value
					//	DON'T accept the default ""
					const std::string answer = userUtils->getChallenge(username);
#ifdef VERBOSE
					std::cout << "@username: " << username << " answer: " << answer << " attempt: " << triedChallenge << "\n";
#endif
					if (answer == "" || triedChallenge != answer) //no challenge registered for this person or wrong answer
					{
						//person doesn't have a challenge to answer or isn't supposed to be
						const std::string invalid = std::to_string(now) + "|invalid";
						logger->insertLog(Log(Log::TAG::LOGIN, invalid, username, Log::TYPE::OUTBOUND, ip).toString());
						write2Client(invalid, clientTableEntry.first);
						removals.push_back(clientTableEntry.first); //nothing useful can come from this socket

						//reset challenge in case it was wrong
						userUtils->setChallenge(username, "");
						continue;
					}

					//for authenticated connections, allow more timeout in case of bad internet
					struct timeval authTimeout;
					authTimeout.tv_sec = AUTHTIMEOUT;
					authTimeout.tv_usec = 0;
					if (setsockopt(clientTableEntry.first, SOL_SOCKET, SO_RCVTIMEO, (char*) &authTimeout, sizeof(authTimeout)) < 0)
					{
						const std::string error = "cannot set timeout for authenticated command socket (" + std::to_string(errno) + ") " + std::string(strerror(errno));
						logger->insertLog(Log(Log::TAG::LOGIN, error, Log::SELF(), Log::TYPE::ERROR, ip).toString());
					}

					//now that the person has successfully logged in, remove the old information.
					//	this person has established new connections so it's 100% sure the old ones aren't
					//	needed anymore.
					const int oldcmd = userUtils->getCommandFd(username);
					if (oldcmd > 0)
					{						//remove old SSL structs to prevent memory leak
#ifdef VERBOSE
					std::cout << "previous command socket/SSL* exists, will remove\n";
#endif
						removals.push_back(oldcmd);
					}

					//dissociate old fd from user otherwise the person will have 2 commandfds listed in
					//	comamandfdMap. remove client will see the old fd pointing to the user and will clear
					//	the user's session key and fds. don't want them cleared as they're now the new ones.
					//	immediately clean up this person's records before all the new stuff goes in
					bool keepudp = false;
					if(commandContents.size() == 5 && commandContents.at(4)=="keepudp")
					{
						keepudp = true;
					}

					if(!keepudp)
					{
						//for cases where you were in a call but your connection died. call record will still be there
						//	since you didn't formally send a call end
						const std::string other = userUtils->getCallWith(username);
						if (other != "")
						{
							sendCallEnd(other);
						}
					}
					userUtils->clearSession(username, keepudp);

					//challenge was correct and wasn't "", set the info
					const std::string sessionkey = SodiumUtils::randomString(SESSION_KEY_LENGTH);
					userUtils->setSessionKey(username, sessionkey);
					userUtils->setCommandFd(sessionkey, clientTableEntry.first);
					userUtils->setChallenge(username, ""); //reset after successful completion

					//send an ok
					std::string resp = std::to_string(now) + "|login2resp|" + sessionkey;
					write2Client(resp, clientTableEntry.first);
#ifndef VERBOSE
					resp = std::to_string(now) + "|login2resp|" + SESSION_KEY_PLACEHOLDER();
#endif
					logger->insertLog(Log(Log::TAG::LOGIN, resp, username, Log::TYPE::OUTBOUND, ip).toString());
					continue; //login command, no session key to verify, continue to the next fd after proccessing login2
				}

				//done processing login commands.
				//all (non login) commands have the format timestamp|COMMAND|(stuff)...sessionkey
				const std::string sessionkey = commandContents.at(commandContents.size() - 1);

#ifndef VERBOSE //unless needed, don't log session keys as they're still in use
				originalBufferCmd.replace(originalBufferCmd.find(sessionkey), SESSION_KEY_LENGTH, SESSION_KEY_PLACEHOLDER());
#endif
				if (!userUtils->verifySessionKey(sessionkey, clientTableEntry.first))
				{
					const std::string error = "INVALID SESSION ID. refusing command (" + originalBufferCmd + ")";
					logger->insertLog(Log(Log::TAG::BADCMD, error, user, Log::TYPE::ERROR, ip).toString());

					const std::string invalid = std::to_string(now) + "|invalid";
					write2Client(invalid, clientTableEntry.first);
					logger->insertLog(Log(Log::TAG::BADCMD, invalid, user, Log::TYPE::OUTBOUND, ip).toString());
					continue;
				}

				//variables written from touma calling zapper perspective
				//command will come from touma's cmd fd
				if (command == "call")
				{//timestamp|call|zapper|toumakey

					const std::string zapper = commandContents.at(2);
					const std::string touma = user;
					logger->insertLog(Log(Log::TAG::CALL, originalBufferCmd, touma, Log::TYPE::INBOUND, ip).toString());
					const int zapperCmdFd = userUtils->getCommandFd(zapper);

					//find out if zapper has a command fd (signed in)
					const bool offline = (zapperCmdFd == 0);
					//make sure zapper isn't already in a call or waiting for one to connect
					const bool busy = (userUtils->getCallWith(zapper) != "");
					//make sure touma didn't accidentally dial himself
					const bool selfDial = (touma == zapper);

					if (offline || busy || selfDial)
					{
						const std::string na = std::to_string(now) + "|end|" + zapper;
						write2Client(na, clientTableEntry.first);
						logger->insertLog(Log(Log::TAG::CALL, na, touma, Log::TYPE::OUTBOUND, ip).toString());
						continue; //nothing more to do
					}

					//setup the user statuses and register the call with user utils
					userUtils->setUserState(zapper, INIT);
					userUtils->setUserState(touma, INIT);
					userUtils->setCallPair(touma, zapper);

					//tell touma that zapper is being rung
					const std::string notifyTouma = std::to_string(now) + "|available|" + zapper;
					write2Client(notifyTouma, clientTableEntry.first);
					logger->insertLog(Log(Log::TAG::CALL, notifyTouma, touma, Log::TYPE::OUTBOUND, ip).toString());

					//tell zapper touma wants to call her
					const std::string notifyZapper = std::to_string(now) + "|incoming|" + touma;
					write2Client(notifyZapper, zapperCmdFd);
					const std::string zapperip = ipFromFd(zapperCmdFd);
					logger->insertLog(Log(Log::TAG::CALL, notifyZapper, zapper, Log::TYPE::OUTBOUND, zapperip).toString());
				}
				//variables written when zapper accepets touma's call
				//command will come from zapper's cmd fd
				else if (command == "accept")
				{					//timestamp|accept|touma|zapperkey
					const std::string zapper = user;
					const std::string touma = commandContents.at(2);
					logger->insertLog(Log(Log::TAG::ACCEPT, originalBufferCmd, zapper, Log::TYPE::INBOUND, ip).toString());

					if (!isRealCall(zapper, touma, Log::TAG::ACCEPT))
					{
						continue;
					}

					//arbitrarily chosen that the one who makes the call (touma) gets to generate the aes key
					const int toumaCmdFd = userUtils->getCommandFd(touma);
					const std::string toumaResp = std::to_string(now) + "|prepare|" + userUtils->getSodiumKeyDump(zapper) + "|" + zapper;
					write2Client(toumaResp, toumaCmdFd);
					logger->insertLog(Log(Log::TAG::ACCEPT, toumaResp, touma, Log::TYPE::OUTBOUND, ipFromFd(toumaCmdFd)).toString());

					//send zapper touma's public key to be able to verify that the aes256 passthrough is actually from him
					const std::string zapperResp = std::to_string(now) + "|prepare|" + userUtils->getSodiumKeyDump(touma) + "|" + touma;
					write2Client(zapperResp, clientTableEntry.first);
					logger->insertLog(Log(Log::TAG::ACCEPT, zapperResp, zapper, Log::TYPE::OUTBOUND, ip).toString());
				}
				else if (command == "passthrough")
				{
					//timestamp|passthrough|zapper|encrypted aes key|toumakey
					const std::string zapper = commandContents.at(2);
					const std::string touma = user;
					const std::string end2EndKeySetup = commandContents.at(3);
					originalBufferCmd.replace(originalBufferCmd.find(end2EndKeySetup), end2EndKeySetup.length(), AES_PLACEHOLDER());
					logger->insertLog(Log(Log::TAG::PASSTHROUGH, originalBufferCmd, user, Log::TYPE::INBOUND, ip).toString());

					if (!isRealCall(touma, zapper, Log::TAG::PASSTHROUGH))
					{
						continue;
					}

					const int zapperfd = userUtils->getCommandFd(zapper);
					std::string direct = std::to_string(now) + "|direct|" + end2EndKeySetup + "|" + touma;					//as in "directly" from touma, not from the server
					write2Client(direct, zapperfd);
					direct.replace(direct.find(end2EndKeySetup), end2EndKeySetup.length(), AES_PLACEHOLDER());
					logger->insertLog(Log(Log::TAG::PASSTHROUGH, direct, zapper, Log::TYPE::OUTBOUND, ipFromFd(zapperfd)).toString());

				}
				else if (command == "ready")
				{					//timestamp|ready|touma|zapperkey
					const std::string zapper = user;
					const std::string touma = commandContents.at(2);
					logger->insertLog(Log(Log::TAG::READY, originalBufferCmd, user, Log::TYPE::INBOUND, ip).toString());
					if (!isRealCall(zapper, touma, Log::TAG::READY))
					{
						continue;
					}

					userUtils->setUserState(zapper, INCALL);
					if (userUtils->getUserState(touma) == INCALL)
					{					//only if both people are ready can  you start the call

						//tell touma zapper accepted his call request
						//	AND confirm to touma, it's zapper he's being connected with
						const int toumaCmdFd = userUtils->getCommandFd(touma);
						const std::string toumaResp = std::to_string(now) + "|start|" + zapper;
						write2Client(toumaResp, toumaCmdFd);
						logger->insertLog(Log(Log::TAG::ACCEPT, toumaResp, touma, Log::TYPE::OUTBOUND, ipFromFd(toumaCmdFd)).toString());

						//confirm to zapper she's being connected to touma
						const std::string zapperResp = std::to_string(now) + "|start|" + touma;
						write2Client(zapperResp, clientTableEntry.first);
						logger->insertLog(Log(Log::TAG::ACCEPT, zapperResp, zapper, Log::TYPE::OUTBOUND, ip).toString());
					}
				}
				//whether it's a call end or call timeout or call reject, the result is the same
				else if (command == "end")
				{ //timestamp|end|zapper|toumakey
					const std::string zapper = commandContents.at(2);
					const std::string touma = user;
					logger->insertLog(Log(Log::TAG::END, originalBufferCmd, touma, Log::TYPE::INBOUND, ip).toString());

					if (!isRealCall(touma, zapper, Log::TAG::END))
					{
						continue;
					}

					sendCallEnd(zapper);
				}
				else //commandContents[1] is not a known command... something fishy???
				{
					logger->insertLog(Log(Log::TAG::BADCMD, originalBufferCmd, userUtils->userFromCommandFd(clientTableEntry.first), Log::TYPE::INBOUND, ip).toString());
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
			for(int deadSock : removals)
			{
				if(clients.count(deadSock) > 0)
				{
					removeClient(deadSock);
				}
			}
			removals.clear();
		}
#ifdef VERBOSE
		std::cout << "_____________________________________\n_________________________________\n";
#endif
	}

	//stop user utilities
	userUtils->killInstance();
	
	//close ports
	close(cmdFD);
	return 0; 
}

void udpThread(int port, const std::unique_ptr<unsigned char[]>& publicKey, const std::unique_ptr<unsigned char[]>& privateKey)
{
	UserUtils* userUtils = UserUtils::getInstance();
	Logger* logger = Logger::getInstance();

	const int mediaPort = port;

	//establish the udp socket for voice data
	int mediaFd;
	struct sockaddr_in mediaInfo;
	setupListeningSocket(SOCK_DGRAM, NULL, &mediaFd, &mediaInfo, mediaPort);

	//make the socket an expedited one
	const int express = IPTOS_DSCP_EF;
	if(setsockopt(mediaFd, IPPROTO_IP, IP_TOS, (char*)&express, sizeof(int)) < 0)
	{
		std::string error="cannot set udp socket dscp expedited (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()).toString());
	}

	std::unique_ptr<unsigned char[]> mediaBufferArray = std::make_unique<unsigned char[]>(MEDIASIZE);
	while(true)
	{
		//setup buffer to receive on udp socket
		unsigned char* mediaBuffer = mediaBufferArray.get();
		memset(mediaBuffer, 0, MEDIASIZE);
		struct sockaddr_in sender;
		socklen_t senderLength = sizeof(struct sockaddr_in);

		//read encrypted voice data or registration
		const int receivedLength = recvfrom(mediaFd, mediaBuffer, MEDIASIZE, 0, (struct sockaddr*)&sender, &senderLength);
		if(receivedLength < 0)
		{
			const std::string error = "udp read error with errno " + std::to_string(errno) + ": " + std::string(strerror(errno));
			logger->insertLog(Log(Log::TAG::UDPTHREAD, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()).toString());
			continue; //received nothing, this round is a write off
		}

		//ip:port, glue address and port together
		const std::string summary = std::string(inet_ntoa(sender.sin_addr)) + ":" + std::to_string(ntohs(sender.sin_port));
		std::string user = userUtils->userFromUdpSummary(summary);
		const ustate state = userUtils->getUserState(user);

		//need to send an ack whether it's for the first time or because the first one went missing.
		if((user == "") || (state == INIT))
		{
#ifdef VERBOSE
			std::cout << "sending ack for summary: " << summary << " belonging to " << user << "/\n";
#endif

			//input: [sodium seal bytes[nonce|message length|encrypted]]

			const std::string ip = std::string(inet_ntoa(sender.sin_addr));

			std::unique_ptr<unsigned char[]> decryptedArray = std::make_unique<unsigned char[]>(MEDIASIZE);
			unsigned char* decrypted = decryptedArray.get(); //extra space will be zeroed creating an automatically zero terminated string
			int unsealok = crypto_box_seal_open(decrypted, mediaBuffer, receivedLength, publicKey.get(), privateKey.get());
			if(unsealok != 0)
			{
				const std::string error = "udp bad unseal";
				logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user , Log::TYPE::ERROR, ip).toString());
				continue; //bad registration
			}

			std::string registration((char*)decrypted);
			if(!legitimateAscii((unsigned char*)registration.c_str(), registration.length()))
			{
				const std::string error = "udp unseal ok, bad ascii";
				logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user , Log::TYPE::ERROR, ip).toString());
				continue; //bad characters in registration
			}

			std::string ogregistration = registration;
			std::vector<std::string> registrationParsed = parse((unsigned char*)registration.c_str());
			if(registrationParsed.size() != REGISTRATION_SEGMENTS)
			{
				const std::string error = "udp unseal ok, ascii ok, bad format: " + ogregistration;
				logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user , Log::TYPE::ERROR, ip).toString());
				continue; //improperly formatted registration
			}

			const std::string sessionkey = registrationParsed.at(1);
			user = userUtils->userFromSessionKey(sessionkey);
			const bool timestampOK = checkTimestamp(registrationParsed.at(0), Log::TAG::UDPTHREAD, ogregistration, user, ip);
			if(!timestampOK)
			{
				const std::string error =  "udp unseal ok, ascii ok, format ok, bad timestamp " + ogregistration;
				logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user , Log::TYPE::ERROR, ip).toString());
				continue;
			}

			//bogus session key
			if(user == "")
			{
				const std::string error = "udp registration key doesn't belong to anyone " + ogregistration;
				logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user , Log::TYPE::ERROR, ip).toString());
				continue;
			}

			//user is somebody, set the udp info
			userUtils->setUdpSummary(sessionkey, summary);
			userUtils->setUdpInfo(sessionkey, sender);

			//if the person is not in a call, there is no need to register a media port
			if(userUtils->getCallWith(user) == "")
			{
				userUtils->clearUdpInfo(user);
				continue;
			}

			//create and encrypt ack
			const time_t now=time(NULL);
			const std::string ack = std::to_string(now);
			std::unique_ptr<unsigned char[]> ackEnc = std::make_unique<unsigned char[]>(COMMANDSIZE);
			int encLength = 0;
			const int userCmdPort = userUtils->getCommandFd(user);
			const std::unique_ptr<unsigned char[]>& userTCPKey = clients[userCmdPort]->getSymmetricKey();
			SodiumUtils::sodiumEncrypt(false, (unsigned char*)ack.c_str(), ack.length(), userTCPKey.get(), NULL, ackEnc, encLength);

			//encryption failed??
			if(encLength == 0)
			{
				const std::string error = "failed to sodium encrypt udp ack???\n";
				logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user , Log::TYPE::ERROR, ip).toString());
				continue;
			}

			//send udp ack: no time like the present to test the 2 way udp connection
			const int sent = sendto(mediaFd, ackEnc.get(), encLength, 0, (struct sockaddr*)&sender, senderLength);
			if(sent < 0)
			{
				const std::string error = "udp sendto failed during media port registration with errno (" + std::to_string(errno) + ") " + std::string(strerror(errno));
				logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user , Log::TYPE::ERROR, ip).toString());
			}
		}
		else if(state == INCALL)
		{//in call, passthrough audio untouched (end to end encryption if only to avoid touching more openssl apis)
			const std::string otherPerson = userUtils->getCallWith(user);

			//if the other person disappears midway through, calling clear session on his socket will cause
			//	you to have nobody listed in User.callWith (or "" default value). getUdpInfo("") won't end well
			if(otherPerson == "")
			{
				continue;
			}


			struct sockaddr_in otherSocket = userUtils->getUdpInfo(otherPerson);
			const int sent = sendto(mediaFd, mediaBuffer, receivedLength, 0, (struct sockaddr*)&otherSocket, sizeof(otherSocket));
			if(sent < 0)
			{
				const std::string error = "udp sendto failed during live call with errno (" + std::to_string(errno) + ") " + std::string(strerror(errno));
				const std::string ip = std::string(inet_ntoa(otherSocket.sin_addr));
				logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user , Log::TYPE::ERROR, ip).toString());
			}
		}
	}
}


//use a vector to prevent reading out of bounds
std::vector<std::string> parse(unsigned char command[])
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

	char* token;
	char* save;
	int i = 0;
	std::vector<std::string> result;
	token = strtok_r((char*)command, "|", &save);
	while(token != NULL && i < COMMAND_MAX_SEGMENTS)
	{
		result.push_back(std::string(token));
		token = strtok_r(NULL, "|", &save);
		i++;
	}
	return result;
}

// sd: a client's socket descriptor
void removeClient(int sd)
{
	UserUtils* userUtils = UserUtils::getInstance();
	const std::string uname = userUtils->userFromCommandFd(sd);

	shutdown(sd, 2);
	close(sd);
	clients.erase(sd);

	//clean up the live list if needed
	userUtils->clearSession(uname, true);
}

//before doing an accept, reject, end command check to see if it's for a real call
//	or someone trying to get smart with the server
bool isRealCall(const std::string& persona, const std::string& personb, Log::TAG tag)
{
	Logger* logger = Logger::getInstance();

	bool real = true;
	UserUtils* userUtils = UserUtils::getInstance();
	const std::string awith = userUtils->getCallWith(persona);
	const std::string bwith = userUtils->getCallWith(personb);
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
		const int fd = userUtils->getCommandFd(persona);
		const std::string ip = ipFromFd(fd);
		const std::string error = persona + " sent a command for a nonexistant call";
		logger->insertLog(Log(tag, error, persona, Log::TYPE::ERROR, ip).toString());

		const time_t now = time(NULL);
		const std::string invalid = std::to_string(now) + "|invalid";
		if(fd > 0)
		{
			write2Client(invalid, fd);
			logger->insertLog(Log(tag, invalid, persona, Log::TYPE::OUTBOUND, ip).toString());
		}
	}
	return real;
}

// write a message to a client
void write2Client(const std::string& response, int sd)
{
	Logger* logger = Logger::getInstance();

	//in case the client disappears suddenly
	if(clients.count(sd) == 0)
	{
		return;
	}

	std::unique_ptr<unsigned char[]> encOutput = std::make_unique<unsigned char[]>(COMMANDSIZE);
	int encOutputLength = 0;
	const std::unique_ptr<Client>& client = clients[sd];

	SodiumUtils::sodiumEncrypt(false, (unsigned char*)(response.c_str()), response.length(), client->getSymmetricKey().get(), NULL, encOutput, encOutputLength);
	const int errValue = write(sd, encOutput.get(), encOutputLength);

	if(errValue == -1)
	{
		UserUtils* userUtils = UserUtils::getInstance();
		const std::string user = userUtils->userFromCommandFd(sd);
		const std::string ip = ipFromFd(sd);
		const std::string error = "write errno " + std::to_string(errno) + " " + std::string(strerror(errno));
		logger->insertLog(Log(Log::TAG::TCP, error, user, Log::TYPE::ERROR, ip).toString());
	}
}

std::string ipFromFd(int sd)
{
	struct sockaddr_in thisfd;
	socklen_t thisfdSize = sizeof(struct sockaddr_in);
	const int result = getpeername(sd, (struct sockaddr*) &thisfd, &thisfdSize);
	if(result == 0)
	{
		return std::string(inet_ntoa(thisfd.sin_addr));
	}
	else
	{
		return "(" +std::to_string(errno) + ": " + std::string(strerror(errno)) + ")";
	}
}

bool legitimateAscii(unsigned char* buffer, int length)
{
	for (int i = 0; i < length; i++)
	{
		const unsigned char byte = buffer[i];

		const bool isSign = ((byte == 43) || (byte == 45));
		const bool isNumber = ((byte >= 48) && (byte <= 57));
		const bool isUpperCase = ((byte >= 65) && (byte <= 90));
		const bool isLowerCase = ((byte >= 97) && (byte <= 122));
		const bool isDelimiter = (byte == 124);

		if (!isSign && !isNumber && !isUpperCase && !isLowerCase && !isDelimiter)
		{//actually only checking for ascii of interest
			return false;
		}
	}
	return true;
}

void sendCallEnd(std::string user)
{
	Logger* logger = Logger::getInstance();

	//reset both peoples's states and remove the call pair record
	UserUtils* userUtils = UserUtils::getInstance();
	const std::string other = userUtils->getCallWith(user);
	userUtils->setUserState(user, NONE);
	userUtils->setUserState(other, NONE);
	userUtils->removeCallPair(user);

	//send the call end
	const std::string resp = std::to_string(time(NULL)) + "|end|" + other;
	const int cmdFd = userUtils->getCommandFd(user);
	write2Client(resp, cmdFd);
	logger->insertLog(Log(Log::TAG::END, resp, user, Log::TYPE::OUTBOUND, ipFromFd(cmdFd)).toString());
}

void socketAccept(int cmdFD, struct timeval* unauthTimeout)
{
	Logger* logger = Logger::getInstance();

	struct sockaddr_in cli_addr;
	socklen_t clilen = sizeof(cli_addr);

	const int incomingCmd = accept(cmdFD, (struct sockaddr*) &cli_addr, &clilen);
	if(incomingCmd < 0)
	{
		const std::string error = "accept system call error (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		logger->insertLog(Log(Log::TAG::INCOMINGCMD, error, Log::SELF(), Log::TYPE::ERROR, Log::DONTKNOW()).toString());
		return;
	}
	const std::string ip = inet_ntoa(cli_addr.sin_addr);

	//for new sockets that nobody owns, don't give much leniency for timeouts
	if(setsockopt(incomingCmd, SOL_SOCKET, SO_RCVTIMEO, (char*)unauthTimeout, sizeof(struct timeval)) < 0)
	{
		const std::string error = "cannot set timeout for incoming command socket (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		logger->insertLog(Log(Log::TAG::INCOMINGCMD, error, Log::SELF(), Log::TYPE::ERROR, ip).toString());
		shutdown(incomingCmd, 2);
		close(incomingCmd);
		return;
	}

	//disable nagle delay for heartbeat which is a 1 char payload
	int nagle = 0;
	if(setsockopt(incomingCmd, IPPROTO_TCP, TCP_NODELAY, (char*)&nagle, sizeof(int)))
	{
		const std::string error = "cannot disable nagle delay (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		logger->insertLog(Log(Log::TAG::INCOMINGCMD, error, Log::SELF(), Log::TYPE::ERROR, ip).toString());
	}
	clients[incomingCmd] = std::unique_ptr<Client>(new Client());
}

bool checkTimestamp(const std::string& tsString, Log::TAG tag, const std::string& errorMessage, const std::string& user, const std::string& ip)
{
	Logger* logger = Logger::getInstance();
	try
	{
		const uint64_t timestamp = (uint64_t) std::stoull(tsString); //catch is for this
		const uint64_t maxError = 60L * MARGIN_OF_ERROR;
		const time_t now=time(NULL);
		const uint64_t timeDifference = std::max((uint64_t) now, timestamp) - std::min((uint64_t) now, timestamp);
		if (timeDifference > maxError)
		{
			//only bother processing the command if the timestamp was valid

			//prepare the error log
			const uint64_t mins = timeDifference / 60;
			const uint64_t seconds = timeDifference - mins * 60;
			const std::string error = "timestamp received was outside the " + std::to_string(MARGIN_OF_ERROR) + " minute margin of error: " + std::to_string(mins) + "mins, " + std::to_string(seconds) + "seconds" + errorMessage;
			logger->insertLog(Log(tag, error, user, Log::TYPE::ERROR, ip).toString());
			return false;
		}
	}
	catch(std::invalid_argument &badarg)
	{ //timestamp couldn't be parsed. assume someone is trying something fishy
		logger->insertLog(Log(tag, "invalid_argument: " + errorMessage, user, Log::TYPE::INBOUND, ip).toString());

		const std::string error="INVALID ARGUMENT EXCEPTION: " + errorMessage;
		logger->insertLog(Log(tag, error, user, Log::TYPE::ERROR, ip).toString());

		return false;
	}
	catch(std::out_of_range &exrange)
	{
		logger->insertLog(Log(tag, "out_of_range: " + errorMessage, user, Log::TYPE::INBOUND, ip).toString());

		const std::string error="OUT OF RANGE: " + errorMessage;
		logger->insertLog(Log(tag, error, user, Log::TYPE::ERROR, ip).toString());

		return false;
	}

	return true;
}
