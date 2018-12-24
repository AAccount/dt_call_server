/*
 * server_init.c
 *
 *  Created on: May 2, 2017
 *      Author: Daniel
 *
 *  Various intialization functions used by the server.
 *  Moved here for readability.
 */
#include "server_init.hpp"

void readServerConfig(int &cmdPort, int &mediaPort, std::string &sodiumPublic, std::string &sodiumPrivate, Logger* logger)
{
	std::ifstream conffile(CONFFILE());
	std::string line;
	bool gotCmdPort = false, gotMediaPort = false, gotSodiumPublic =false, gotSodiumPrivate = false;

	while(getline(conffile, line))
	{
		//skip blank lines and comment lines
		if(line.length() == 0 || line.at(0) == '#')
		{
			continue;
		}

		//read the variable and its value
		std::string var, value;
		std::stringstream ss(line);
		std::getline(ss, var, '=');
		std::getline(ss, value, '=');

		//cleanup the surrounding whitespace and strip the end of line comment
		var = Utils::trim(var);
		value = Utils::trim(value);

		//if there is no value then go on to the next line
		if(value == "")
		{
			continue;
		}

		if(var == "command")
		{
			cmdPort = atoi(value.c_str());
			gotCmdPort = true;
			continue;
		}
		else if (var == "media")
		{
			mediaPort = atoi(value.c_str());
			gotMediaPort = true;
			continue;
		}
		else if(var == "public_sodium")
		{
			std::string keyDump = Utils::dumpSmallFile(value);
			if(SodiumUtils::checkSodiumPublic(keyDump))
			{
				std::string header = SodiumUtils::SODIUM_PUBLIC_HEADER();
				sodiumPublic = keyDump.substr(header.length(), crypto_box_PUBLICKEYBYTES*3);
				gotSodiumPublic = true;
			}
			else
			{
				std::cerr << "server sodium public key error\n";
			}
		}
		else if(var == "private_sodium")
		{
			std::string keyDump = Utils::dumpSmallFile(value);
			if(SodiumUtils::checkSodiumPrivate(keyDump))
			{
				std::string header = SodiumUtils::SODIUM_PRIVATE_HEADER();
				sodiumPrivate = keyDump.substr(header.length(), crypto_box_SECRETKEYBYTES*3);
				gotSodiumPrivate = true;
			}
			else
			{
				std::cerr << "server sodium private key error\n";
			}
		}
		else
		{
			std::string unknown = "unknown variable parsed: " + line;
			logger->insertLog(Log(Log::TAG::STARTUP, unknown, Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()));
		}
	}

	//at the minimum a public and private key must be specified. everything else has a default value
	if (!gotSodiumPublic || !gotSodiumPrivate)
	{
		if(!gotSodiumPublic)
		{
			std::string error = "Your did not specify a SODIUM PUBLIC key in: " + CONFFILE() + "\n";
			std::cerr << error << "\n";
		}
		if(!gotSodiumPrivate)
		{
			std::string error = "Your did not specify a SODIUM PRIVATE key in: " + CONFFILE() + "\n";
			std::cerr << error << "\n";
		}
		exit(1);
	}

	//warn of default values if they're being used
	if(!gotCmdPort)
	{
		std::string message =  "Using default command port of: " + std::to_string(cmdPort);
		logger->insertLog(Log(Log::TAG::STARTUP, message, Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()));
	}
	if(!gotMediaPort)
	{
		std::string message= "Using default media port of: " + std::to_string(mediaPort);
		logger->insertLog(Log(Log::TAG::STARTUP, message, Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()));
	}

}

void setupListeningSocket(int type, struct timeval* timeout, int* fd, struct sockaddr_in* info, int port)
{
	//setup command port to accept new connections
	*fd = socket(AF_INET, type, 0); //tcp socket
	if(*fd < 0)
	{
		std::string error = "cannot establish socket (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		std::cerr << error << "\n";
		exit(1);
	}
	memset((char*) info, 0, sizeof(struct sockaddr_in));
	info->sin_family = AF_INET; //ipv4
	info->sin_addr.s_addr = INADDR_ANY; //listen on any nic
	info->sin_port = htons(port);
	if(bind(*fd, (struct sockaddr*)info, sizeof(struct sockaddr_in)) < 0)
	{
		std::string error = "cannot bind socket to a nic (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		std::cerr << error << "\n";
		exit(1);
	}

	if(type == SOCK_STREAM)
	{
		if(setsockopt(*fd, SOL_SOCKET, SO_RCVTIMEO, (char*)timeout, sizeof(struct timeval)) < 0)
		{
			std::string error="cannot set tcp socket options (" + std::to_string(errno) + ") " + std::string(strerror(errno));
			std::cerr << error << "\n";
			exit(1);
		}
		listen(*fd, MAXLISTENWAIT);
	}
}
