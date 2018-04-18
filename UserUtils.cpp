/*
 * UserUtils.cpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#include "UserUtils.hpp"

//static members
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
	std::ifstream usersfile(USERSFILE());
	std::string line;

	while(std::getline(usersfile, line))
	{
		//skip blank lines and comment lines
		if(line.length() == 0 || line.at(0) == '#')
		{
			continue;
		}

		//read the name and password
		std::string name, publicKeyPath;
		std::stringstream ss(line);
		getline(ss, name, '>');
		getline(ss, publicKeyPath, '>');

		//cleanup the surrounding whitespace and strip the end of line comment
		name = Utils::trim(name);
		publicKeyPath = Utils::trim(publicKeyPath);

		//need both a name and a public key to continue
		if(name == "" || publicKeyPath == "")
		{
			std::cerr << "Account '" << name << "' is misconfigured\n";
			continue;
		}

		//read the user's sodium public key into a file
		std::string sodiumKeyDump = Utils::dumpSmallFile(publicKeyPath);
		std::string sodiumKeyDumpOriginal = sodiumKeyDump;

		//destringify the user's sodium public key
		unsigned char publicKeyBytes[crypto_box_PUBLICKEYBYTES];
		if(!Utils::checkSodiumPublic(sodiumKeyDump))
		{
			std::cerr << "User sodium public key error for: " << name << "\n";
			continue;
		}
		std::string header = SODIUM_PUBLIC_HEADER();
		sodiumKeyDump = sodiumKeyDump.substr(header.length(), crypto_box_PUBLICKEYBYTES*3);
		Utils::destringify(sodiumKeyDump, publicKeyBytes);

		//finally create the user object
		User *user = new User(name, publicKeyBytes, sodiumKeyDumpOriginal);

		//in case the same person has ???2 entries??? get rid of the old one
		if(nameMap.count(name) > 0)
		{
			delete nameMap[name];
			nameMap.erase(name);
			std::cerr << "Duplicate account entry for: " << name << "\n";
		}
		nameMap[name] = user;
	}
	usersfile.close();
}

UserUtils::~UserUtils()
{
	//only thing that matters is to remove all user objects in the heap
	//	no need to undo all maps, they will be killed automatically
	for(auto entry : nameMap)
	{
		delete nameMap[entry.first];
		nameMap[entry.first] = NULL;
	}
}

bool UserUtils::getSodiumPublicKey(const std::string& username, unsigned char (&output)[crypto_box_PUBLICKEYBYTES]) const
{
	if(nameMap.count(username) > 0)
	{
		nameMap.at(username)->getSodiumPublicKey(output);
		return true;
	}
	return false;
}

std::string UserUtils::getSodiumKeyDump(const std::string& uname) const
{
	if(nameMap.count(uname) > 0)
	{
		User* user = nameMap.at(uname);
		return user->getSodiumPublicKeyDump();
	}
	return "";
}

std::string UserUtils::getChallenge(std::string const &username) const
{
	if(nameMap.count(username) > 0)
	{
		return nameMap.at(username)->getChallenge();
	}
	return "";
}

void UserUtils::setChallenge(std::string const &username, std::string challenge)
{
	if(nameMap.count(username) > 0)
	{
		nameMap[username]->setChallenge(challenge);
	}
	else
	{
		std::string error = "trying to set challenge for somebody that doesn't exist: " + username;
		Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	}
}

void UserUtils::setSessionKey(std::string const &username, std::string sessionkey)
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
		Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	}
}

void UserUtils::setCommandFd(std::string const &sessionid, int fd)
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
		Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	}
}

void UserUtils::clearSession(std::string const &username)
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

		removeCallPair(username);
		//don't reset the challenge because when old fds exist when doing login1
		//	the challenge that is set will be erased at the end of that select round.
		//	on the next round when doing login2 it will look like a fake/hacked login
	}
	else
	{
		std::string error = "trying to clear a session for somebody that doesn't exist: " + username;
		Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	}
}

bool UserUtils::verifySessionKey(std::string const &sessionid, int fd) const
{
	if(sessionkeyMap.count(sessionid) == 0)
	{
		return false;
	}

	User *user = sessionkeyMap.at(sessionid);
	return user->getCommandfd() == fd;
}

std::string UserUtils::userFromCommandFd(int fd) const
{
	if (commandfdMap.count(fd) > 0)
	{
		return commandfdMap.at(fd)->getUname();
	}

	std::string error="no user matches the command fd supplied";
	Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	return "";
}

std::string UserUtils::userFromSessionKey(std::string const &sessionid) const
{
	if(sessionkeyMap.count(sessionid) > 0)
	{
		return sessionkeyMap.at(sessionid)->getUname();
	}
	std::string error = "no user matches the session id supplied";
	Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	return "";
}

int UserUtils::getCommandFd(std::string const &user) const
{
	if(nameMap.count(user) > 0)
	{
		User *userObj = nameMap.at(user);
		return userObj->getCommandfd();
	}
	std::string error = "tried to get a comamnd fd for somebody that doesn't exist: " + user;
	Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	return 0;
}

std::string UserUtils::getSessionKey(std::string const &uname) const
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap.at(uname)->getSessionkey();
	}
	std::string error = "tried to get a session key for somebody that doesn't exist: " + uname;
	Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	return "";
}

std::string UserUtils::userFromUdpSummary(std::string const &summary) const
{
	if(udpMap.count(summary) > 0)
	{
		return udpMap.at(summary)->getUname();
	}
	return "";
}

void UserUtils::setUdpSummary(std::string const &sessionkey, std::string summary)
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
		Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	}
}

void UserUtils::setUdpInfo(std::string const &sessionkey, struct sockaddr_in info)
{
	if(sessionkeyMap.count(sessionkey) > 0)
	{
		User *user = sessionkeyMap[sessionkey];
		user->setUdpInfo(info);
	}
	else
	{
		std::string error = "tried to set a udp sockaddr_in for an unregistered session key";
		Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	}
}

struct sockaddr_in UserUtils::getUdpInfo(std::string const &uname) const
{
	return nameMap.at(uname)->getUdpInfo();
}

void UserUtils::clearUdpInfo(std::string const &uname)
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
		Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	}
}

ustate UserUtils::getUserState(std::string const &uname) const
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap.at(uname)->getUserState();
	}
	return INVALID;
}

void UserUtils::setUserState(std::string const &uname, ustate newstate)
{
	if(nameMap.count(uname) > 0)
	{
		nameMap[uname]->setUserState(newstate);
	}
	else
	{
		std::string error = "tried to set user state for somebody that doesn't exist: " + uname;
		Logger::getInstance()->insertLog(Log(Log::TAG::USERUTILS, error, Log::SELF(), Log::TYPE::ERROR, Log::SELFIP()));
	}
}


std::string UserUtils::getCallWith(std::string const &uname) const
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap.at(uname)->getCallWith();
	}
	return "";
}
void UserUtils::setCallPair(std::string uname, std::string newOther)
{
	if(nameMap.count(uname) > 0 && nameMap.count(newOther) > 0)
	{
		nameMap[uname]->setCallWith(newOther);
		nameMap[newOther]->setCallWith(uname);
	}
}

void UserUtils::removeCallPair(std::string const &uname)
{
	if(nameMap.count(uname) > 0 && nameMap.count(nameMap[uname]->getCallWith()) > 0)
	{
		std::string other = nameMap[uname]->getCallWith();
		nameMap[uname]->setCallWith("");
		nameMap[other]->setCallWith("");
	}
}

void UserUtils::killInstance()
{
	delete instance;
}
