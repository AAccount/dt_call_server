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

void initDtOperator(int argc, char* argv[], int& commandFd, int& mediaFd, const std::unique_ptr<unsigned char[]>& publicKey, const std::unique_ptr<unsigned char[]>& privateKey)
{
	std::string settingsLocation = "/etc/dtoperator";
	std::string logLocation = "/var/log/dtoperator";
	parseArgv(argc, argv, settingsLocation, logLocation);
	Logger::setLogLocation(logLocation);
	UserUtils::setFileLocation(settingsLocation);

	Logger* logger = Logger::getInstance();
	const std::string start = "starting call operator V" + VERSION;
	logger->insertLog(Log(Log::TAG::STARTUP, start, Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()).toString());
	
	int cmdPort, mediaPort;
	std::string sodiumPublicString, sodiumPrivateString;
	readServerConfig(settingsLocation, cmdPort, mediaPort, sodiumPublicString, sodiumPrivateString, logger);

	commandFd = setupCommandFd(cmdPort);
	mediaFd = setupMediaFd(mediaPort, logger);

	initializeSodiumKeys(logger, sodiumPublicString, sodiumPrivateString, publicKey, privateKey);
	ignoreSigPipe();
}

void readServerConfig(const std::string& settingsLocation, int& cmdPort, int& mediaPort, std::string& sodiumPublic, std::string& sodiumPrivate, Logger* logger)
{
	const std::string FILE_NAME = "dtoperator.conf";
	const std::string fileLocation = settingsLocation + "/" + FILE_NAME;
	if(!std::filesystem::exists(fileLocation))
	{
		std::cerr << "config file " << FILE_NAME << " not found in " << fileLocation << "\n";
		exit(1);
	}
	
	std::ifstream conffile(fileLocation);
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
		var = ServerUtils::trim(var);
		value = ServerUtils::trim(value);

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
			std::string keyDump = ServerUtils::dumpSmallFile(value);
			if(SodiumUtils::checkSodiumPublic(keyDump))
			{
				std::string header = SodiumUtils::SODIUM_PUBLIC_HEADER;
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
			std::string keyDump = ServerUtils::dumpSmallFile(value);
			if(SodiumUtils::checkSodiumPrivate(keyDump))
			{
				std::string header = SodiumUtils::SODIUM_PRIVATE_HEADER;
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
			logger->insertLog(Log(Log::TAG::STARTUP, unknown, Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()).toString());
		}
	}

	//at the minimum a public and private key must be specified. everything else has a default value
	if (!gotSodiumPublic || !gotSodiumPrivate)
	{
		if(!gotSodiumPublic)
		{
			std::string error = "Your did not specify a SODIUM PUBLIC key in: " + fileLocation + "\n";
			std::cerr << error << "\n";
		}
		if(!gotSodiumPrivate)
		{
			std::string error = "Your did not specify a SODIUM PRIVATE key in: " + fileLocation + "\n";
			std::cerr << error << "\n";
		}
		exit(1);
	}

	//warn of default values if they're being used
	if(!gotCmdPort)
	{
		std::string message =  "Using default command port of: " + std::to_string(cmdPort);
		logger->insertLog(Log(Log::TAG::STARTUP, message, Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()).toString());
	}
	if(!gotMediaPort)
	{
		std::string message= "Using default media port of: " + std::to_string(mediaPort);
		logger->insertLog(Log(Log::TAG::STARTUP, message, Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()).toString());
	}

}

void setupListeningSocket(int type, struct timeval* timeout, int* fd, struct sockaddr_in* info, int port)
{
	//setup command port to accept new connections
	*fd = socket(AF_INET, type, 0); //tcp socket
	if(*fd < 0)
	{
		std::string error = "cannot establish socket " + ServerUtils::printErrno();
		std::cerr << error << "\n";
		exit(1);
	}
	memset((char*) info, 0, sizeof(struct sockaddr_in));
	info->sin_family = AF_INET; //ipv4
	info->sin_addr.s_addr = INADDR_ANY; //listen on any nic
	info->sin_port = htons(port);
	if(bind(*fd, (struct sockaddr*)info, sizeof(struct sockaddr_in)) < 0)
	{
		std::string error = "cannot bind socket to a nic " + ServerUtils::printErrno();
		std::cerr << error << "\n";
		exit(1);
	}

	if(type == SOCK_STREAM)
	{
		if(setsockopt(*fd, SOL_SOCKET, SO_RCVTIMEO, (char*)timeout, sizeof(struct timeval)) < 0)
		{
			std::string error="cannot set tcp socket options SO_RCVTIMEO " + ServerUtils::printErrno();
			std::cerr << error << "\n";
			exit(1);
		}
		const int reuse = 1;
		if(setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(int)) < 0)
		{
			std::string error="cannot set tcp socket options SO_REUSEADDR " + ServerUtils::printErrno();
			std::cerr << error << "\n";
			exit(1);
		}
		listen(*fd, MAXLISTENWAIT);
	}
}

void parseArgv(int argc, char* argv[], std::string& settingsLocation, std::string& logLocation)
{
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
}

void ignoreSigPipe()
{
	//sigpipe is thrown for closing the broken connection. it's gonna happen for a voip server handling mobile clients
	//what're you gonna do about it... IGNORE IT!!
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
}

int setupCommandFd(int cmdPort)
{
	struct timeval unauthTimeout; //for new sockets
	unauthTimeout.tv_sec = 0;
	unauthTimeout.tv_usec = UNAUTHTIMEOUT;

	int cmdFd;
	struct sockaddr_in serv_cmd;
	setupListeningSocket(SOCK_STREAM, &unauthTimeout, &cmdFd, &serv_cmd, cmdPort);
	return cmdFd;
}

int setupMediaFd(int mediaPort, Logger* logger)
{
	int mediaFd;
	struct sockaddr_in mediaInfo;
	setupListeningSocket(SOCK_DGRAM, NULL, &mediaFd, &mediaInfo, mediaPort);

	//make the socket an expedited one
	const int express = IPTOS_DSCP_EF;
	if(setsockopt(mediaFd, IPPROTO_IP, IP_TOS, (char*)&express, sizeof(int)) < 0)
	{
		std::string error="cannot set udp socket dscp expedited " + ServerUtils::printErrno();
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()).toString());
	}
	return mediaFd;
}

void initializeSodiumKeys(Logger* logger, std::string& publicString, std::string& privateString, const std::unique_ptr<unsigned char[]>& publicKey, const std::unique_ptr<unsigned char[]>& privateKey)
{
	if(sodium_init() < 0)
	{
		logger->insertLog(Log(Log::TAG::STARTUP, "couldn't initialize sodium library", Log::SELF(), Log::TYPE::SYSTEM, Log::SELFIP()).toString());
		exit(1);
	}

	Stringify::destringify(publicString, publicKey.get());
	char* sodiumPublicStringMemory = &publicString[0];
	randombytes_buf(sodiumPublicStringMemory, publicString.length());

	Stringify::destringify(privateString, privateKey.get());
	char* sodiumPrivateStringMemory = &privateString[0];
	randombytes_buf(sodiumPrivateStringMemory, privateString.length());
}