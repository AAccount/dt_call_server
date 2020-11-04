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
	const std::unique_ptr<unsigned char[]> sodiumPublicKey = std::make_unique<unsigned char[]>(crypto_box_PUBLICKEYBYTES);
	const std::unique_ptr<unsigned char[]> sodiumPrivateKey = std::make_unique<unsigned char[]>(crypto_box_SECRETKEYBYTES);
	int cmdFD, mediaFd;
	initDtOperator(argc, argv, cmdFD, mediaFd, sodiumPublicKey, sodiumPrivateKey);

	Logger* logger = Logger::getInstance();
	UserUtils* userUtils = UserUtils::getInstance();

	try
	{
		std::thread udpThreadObj(udpThread, mediaFd, std::ref(sodiumPublicKey), std::ref(sodiumPrivateKey));
		udpThreadObj.detach();
	}
	catch(std::system_error& e)
	{
		std::string error = "cannot create the udp thread (" + std::string(e.what()) + ") ";
		logger->insertLog(Log(Log::TAG::STARTUP, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()).toString());
		exit(1);
	}

	while(true)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(cmdFD, &readfds);
		int maxsd = cmdFD;

		for(const auto& clientMapping : clients)
		{
			int sd = clientMapping.first;
			FD_SET(sd, &readfds);
			maxsd = (sd > maxsd) ? sd : maxsd;
		}

		if(select(maxsd+1, &readfds, NULL, NULL, NULL) < 0)
		{
			std::string error = "read fds select system call error (" + std::to_string(errno) + ") " + std::string(strerror(errno));
			logger->insertLog(Log(Log::TAG::STARTUP, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()).toString());
			exit(1); //see call thread fx for why
		}

		if(FD_ISSET(cmdFD, &readfds))
		{
			struct timeval unauthTimeout; //for new sockets
			unauthTimeout.tv_sec = 0;
			unauthTimeout.tv_usec = UNAUTHTIMEOUT;
			socketAccept(cmdFD, &unauthTimeout);
		}

		std::vector<int> removals;
		for(const auto& clientTableEntry : clients)
		{
			int fd = clientTableEntry.first;
			Client* client = clientTableEntry.second.get();
			std::unique_ptr<unsigned char[]> inputBuffer = std::make_unique<unsigned char[]>(COMMANDSIZE);
			if(FD_ISSET(fd, &readfds))
			{
				const int amountRead = read(clientTableEntry.first, inputBuffer.get(), COMMANDSIZE);
				if(amountRead < 1)
				{
					removals.push_back(clientTableEntry.first);
					continue;
				}
				
				const std::string user=userUtils->userFromCommandFd(fd);
				CommandContext preDecryptCtx(logger, userUtils, fd, client, clients, "", std::vector<std::string>(), user, removals);

				if(client->isNew())
				{
					initClient(preDecryptCtx, inputBuffer, amountRead, sodiumPublicKey, sodiumPrivateKey);
					continue; //sent the initial key. nothing left to do for this client
				}

				std::vector<std::string> commandContents;
				std::string originalBufferCmd;
				if(!decryptCommand(preDecryptCtx, inputBuffer, amountRead, client->getSymmetricKey(), originalBufferCmd, commandContents))
				{
					continue;
				}

				CommandContext postDecryptCtx(logger, userUtils, fd, client, clients, originalBufferCmd, commandContents, user, removals);
				const std::string command = commandContents.at(1);
				if (command == "login1")
				{
					login1(postDecryptCtx, sodiumPrivateKey);
				}
				else if (command == "login2")
				{ 
					login2(postDecryptCtx);
				}
				else if (command == "call")
				{
					cmdCall(postDecryptCtx);
				}
				else if (command == "accept")
				{					
					cmdAccept(postDecryptCtx);
				}
				else if (command == "passthrough")
				{
					cmdPassthrough(postDecryptCtx);
				}
				else if (command == "ready")
				{				
					cmdReady(postDecryptCtx);
				}
				else if (command == "end")
				{ 
					cmdEnd(postDecryptCtx);
				}
				else
				{
					const std::string ip = ipFromFd(fd);
					logger->insertLog(Log(Log::TAG::BADCMD, originalBufferCmd, userUtils->userFromCommandFd(clientTableEntry.first), Log::TYPE::INBOUND, ip).toString());
				}
			}
		}

		//now that all fds are finished inspecting, remove any of them that are dead.
		//don't mess with the map contents while the iterator is live.
		//removing while runnning causes segfaults because if the removed item gets iterated over after removal
		//it's no longer there so you get a segfault
		if(removals.size() > 0)
		{
			for(int deadSock : removals)
			{
				if(clients.count(deadSock) > 0)
				{
					removeClient(deadSock);
				}
			}
			removals.clear();
		}
	}

	userUtils->killInstance();
	close(cmdFD);
	return 0; 
}

void udpThread(int mediaFd, const std::unique_ptr<unsigned char[]>& publicKey, const std::unique_ptr<unsigned char[]>& privateKey)
{
	UserUtils* userUtils = UserUtils::getInstance();
	Logger* logger = Logger::getInstance();

	while(true)
	{
		std::unique_ptr<unsigned char[]> mediaBuffer = std::make_unique<unsigned char[]>(MEDIASIZE);
		struct sockaddr_in sender;
		socklen_t senderLength = sizeof(struct sockaddr_in);

		const int receivedLength = recvfrom(mediaFd, mediaBuffer.get(), MEDIASIZE, 0, (struct sockaddr*)&sender, &senderLength);
		if(receivedLength < 0)
		{
			const std::string error = "udp read error with errno " + std::to_string(errno) + ": " + std::string(strerror(errno));
			logger->insertLog(Log(Log::TAG::UDPTHREAD, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()).toString());
			continue; //received nothing, this round is a write off
		}

		const std::string summary = std::string(inet_ntoa(sender.sin_addr)) + ":" + std::to_string(ntohs(sender.sin_port));
		std::string user = userUtils->userFromUdpSummary(summary);
		const ustate state = userUtils->getUserState(user);

		//need to send an ack whether it's for the first time or because the first one went missing.
		if((user == "") || (state == INIT))
		{
			//input: [sodium seal bytes[nonce|message length|encrypted]]
			UdpContext initCtx(logger, userUtils, publicKey, privateKey, sender, senderLength, mediaFd, user);
			if(udpDecrypt(initCtx, mediaBuffer, receivedLength))
			{
				udpRegister(initCtx, clients);
			}
		}
		else if(state == INCALL)
		{
			UdpContext ctx(logger, userUtils, publicKey, privateKey, sender, senderLength, mediaFd, user);
			udpCall(ctx, mediaBuffer, receivedLength);
		}
	}
}

void removeClient(int fd)
{
	UserUtils* userUtils = UserUtils::getInstance();
	const std::string uname = userUtils->userFromCommandFd(fd);

	shutdown(fd, 2);
	close(fd);
	clients.erase(fd);

	userUtils->clearSession(uname, true);
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
