/*
 * UserUtils.cpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#include "const.h"
#include "UserUtils.hpp"

//static user utils instance
UserUtils* UserUtils::instance;

UserUtils* UserUtils::getInstance()
{
	if(instance == NULL)
	{
		instance = new UserUtils();
	}
	return instance;
}

UserUtils::UserUtils()
{
	//generate all user objects and have them accessible by name
	std::ifstream usersfile(USERSFILE);
	std::string line;

	while(std::getline(usersfile, line))
	{
		//skip blank lines and comment lines
		if(line.length() == 0 || line.at(0) == '#')
		{
			continue;
		}

		//read the name and password
		std::string name, publicKey, publicKeyDump;
		std::stringstream ss(line);
		getline(ss, name, ' ');
		getline(ss, publicKey, ' ');

		//cleanup the surrounding whitespace and strip the end of line comment
		name = Utils::trim(name);
		publicKey = Utils::trim(publicKey);

		//need both a name and a public key to continue
		if(name == "" || publicKey == "")
		{
			std::cout << "Account '" << name << "' is misconfigured\n";
			continue;
		}

		//open the public key file
		FILE *publicKeyFile = fopen(publicKey.c_str(), "r");
		if(publicKeyFile == NULL)
		{
			std::cout << "Having problems opening " << name << "'s public key file\n";
			continue;
		}

		//turn the file into a useable public key
		RSA *rsaPublic = PEM_read_RSA_PUBKEY(publicKeyFile, NULL, NULL, NULL);
		if(rsaPublic == NULL)
		{
			std::cout << "Could not generate a public key from file for: " << name << "\n";
			continue;
		}
		else //get the dump for end to end encryption
		{
			std::ifstream publicKeyStream(publicKey);
			std::stringstream buffer;
			buffer << publicKeyStream.rdbuf();
			publicKeyDump = buffer.str();
		}
		fclose(publicKeyFile);

		User *user = new User(name, rsaPublic, publicKeyDump);

		//in case the same person has ???2 entries??? get rid of the old one
		if(nameMap.count(name) > 0)
		{
			delete nameMap[name];
			nameMap.erase(name);
			std::cout << "Duplicate account entry for: " << name << "\n";
		}
		nameMap[name] = user;
	}
	usersfile.close();

	//setup the log output
	logTimeT = time(NULL);
	std::string nowString = std::string(ctime(&logTimeT));
	std::string logName = std::string(LOGPREFIX) + nowString.substr(0, nowString.length()-1);
	logfile.open(LOGFOLDER+logName);
}

UserUtils::~UserUtils()
{
	//only thing that matters is to remove all user objects in the heap
	//	no need to undo all maps, they will be killed automatically
	for(auto it = nameMap.begin(); it != nameMap.end(); ++it)
	{
		delete nameMap[it->first];
		nameMap[it->first] = NULL;
	}
}

RSA* UserUtils::getPublicKey(std::string username)
{
	if(nameMap.count(username) > 0)
	{
		return nameMap[username]->getPublicKey();
	}
	return NULL;
}

std::string UserUtils::getChallenge(std::string username)
{
	if(nameMap.count(username) > 0)
	{
		return nameMap[username]->getChallenge();
	}
	return "";
}

void UserUtils::setChallenge(std::string username, std::string challenge)
{
	if(nameMap.count(username) > 0)
	{
		nameMap[username]->setChallenge(challenge);
	}
	else
	{
		std::string error = "trying to set challenge for somebody that doesn't exist: " + username;
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

void UserUtils::setSessionKey(std::string username, std::string sessionkey)
{
	if(nameMap.count(username) > 0)
	{
		User *user = nameMap[username];
		user->setSessionkey(sessionkey);
		sessionkeyMap[sessionkey] = user;
	}
	else
	{
		std::string error = "trying to set a session key for somebody that doesn't exist: " + username;
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

void UserUtils::setCommandFd(std::string sessionid, int fd)
{
	if(sessionkeyMap.count(sessionid) > 0)
	{
		User *user = sessionkeyMap[sessionid];
		user->setCommandfd(fd);
		commandfdMap.erase(fd);
		commandfdMap[fd] = user;
	}
	else
	{
		std::string error = "trying to set a command file descriptor for a session that isn't registered";
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

void UserUtils::clearSession(std::string username)
{
	if(nameMap.count(username) > 0)
	{
		User *user = nameMap[username];

		//remove session key
		sessionkeyMap.erase(user->getSessionkey());
		user->setSessionkey("");

		//remove command fd
		commandfdMap.erase(user->getCommandfd());
		user->setCommandfd(0);

		//remove udp info
		clearUdpInfo(username);

		user->setSessionkey("");
		user->setUserState(NONE);
		//don't reset the challenge because when old fds exist when doing login1
		//	the challenge that is set will be erased at the end of that select round.
		//	on the next round when doing login2 it will look like a fake/hacked login
	}
	else
	{
		std::string error = "trying to clear a session for somebody that doesn't exist: " + username;
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

bool UserUtils::verifySessionKey(std::string sessionid, int fd)
{
	if(sessionkeyMap.count(sessionid) == 0)
	{
		return false;
	}

	User *user = sessionkeyMap[sessionid];
	return user->getCommandfd() == fd;
}

std::string UserUtils::userFromCommandFd(int fd)
{
	if (commandfdMap.count(fd) > 0)
	{
		return commandfdMap[fd]->getUname();
	}

	std::string error="no user matches the command fd supplied";
	insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	return "";
}

std::string UserUtils::userFromSessionKey(std::string sessionid)
{
	if(sessionkeyMap.count(sessionid) > 0)
	{
		return sessionkeyMap[sessionid]->getUname();
	}
	std::string error = "no user matches the session id supplied";
	insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	return "";
}

int UserUtils::getCommandFd(std::string user)
{
	if(nameMap.count(user) > 0)
	{
		User *userObj = nameMap[user];
		return userObj->getCommandfd();
	}
	std::string error = "tried to get a comamnd fd for somebody that doesn't exist: " + user;
	insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	return 0;
}

std::string UserUtils::getSessionKey(std::string uname)
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap[uname]->getSessionkey();
	}
	std::string error = "tried to get a session key for somebody that doesn't exist: " + uname;
	insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	return "";
}

std::string UserUtils::userFromUdpSummary(std::string summary)
{
	if(udpMap.count(summary) > 0)
	{
		return udpMap[summary]->getUname();
	}
	return "";
}

void UserUtils::setUdpSummary(std::string sessionkey, std::string summary)
{
	if(sessionkeyMap.count(sessionkey) > 0)
	{
		User *user = sessionkeyMap[sessionkey];
		user->setUdpSummary(summary);
		udpMap[summary] = user;
	}
	else
	{
		std::string error = "tried to set a udp summary for an unregistered session key";
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

void UserUtils::setUdpInfo(std::string sessionkey, struct sockaddr_in info)
{
	if(sessionkeyMap.count(sessionkey) > 0)
	{
		User *user = sessionkeyMap[sessionkey];
		user->setUdpInfo(info);
	}
	else
	{
		std::string error = "tried to set a udp sockaddr_in for an unregistered session key";
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

struct sockaddr_in UserUtils::getUdpInfo(std::string uname)
{
	return nameMap[uname]->getUdpInfo();
}

void UserUtils::clearUdpInfo(std::string uname)
{
	if(nameMap.count(uname) > 0)
	{
		User *user = nameMap[uname];
		udpMap.erase(user->getUdpSummary());
		user->setUdpSummary("");
		struct sockaddr_in clear;
		memset((char*)&clear, 0, sizeof(struct sockaddr_in));
		user->setUdpInfo(clear);
		user->setUserState(NONE);
	}
	else
	{
		std::string error = "tried to clear udp info for somebody that doesn't exist: " + uname;
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

ustate UserUtils::getUserState(std::string uname)
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap[uname]->getUserState();
	}
	return INVALID;
}

void UserUtils::setUserState(std::string uname, ustate newstate)
{
	if(nameMap.count(uname) > 0)
	{
		nameMap[uname]->setUserState(newstate);
	}
	else
	{
		std::string error = "tried to set user state for somebody that doesn't exist: " + uname;
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

std::string UserUtils::getPublicKeyDump(std::string uname)
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap[uname]->getPublicKeyDump();
	}
	return "";
}

void UserUtils::killInstance()
{
	delete instance;
}

void UserUtils::insertLog(Log dbl)
{
	//figure out if the current log is over 1 day old
	time_t now = time(NULL);
	if((now - logTimeT) > 60*60*24)
	{//if the log is too old, close it and start another one
		logfile.close();
		logTimeT = now;
		std::string nowString = std::string(ctime(&logTimeT));
		std::string logName = std::string(LOGPREFIX) + nowString.substr(0, nowString.length()-1);
		logfile.open(LOGFOLDER+logName);
	}
	logfile << dbl << "\n";
	logfile.flush(); // write immediately to the file

	if(dbl.getType() == ERRORLOG)
	{//make errors dead obvious when testing
		std::cerr << dbl << "\n";
	}
	else
	{
		std::cout << dbl << "\n";
	}
}
