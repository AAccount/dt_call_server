/*
 * UserUtils.cpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#include "const.h"
#include "UserUtils.hpp"

using namespace std;

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
	ifstream usersfile(USERSFILE);
	string line;

	while(getline(usersfile, line))
	{
		//skip blank lines and comment lines
		if(line.length() == 0 || line.at(0) == '#')
		{
			continue;
		}

		//read the name and password
		string name, hash;
		stringstream ss(line);
		getline(ss, name, ' ');
		getline(ss, hash, ' ');

		//cleanup the surrounding whitespace and strip the end of line comment
		name = Utils::trim(name);
		hash = Utils::trim(hash);

		//need both a name and password to continue
		if(name == "" || hash == "")
		{
			continue;
		}

		User *user = new User(name, hash);

		//in case the same person has ???2 entries??? get rid of the old one
		if(nameMap.count(name) > 0)
		{
			delete nameMap[name];
			nameMap.erase(name);
			cout << "Duplicate account entry for: " << name << "\n";
		}
		nameMap[name] = user;
	}
	usersfile.close();

	//setup the log output
	logTimeT = time(NULL);
	string nowString = string(ctime(&logTimeT));
	string logName = string(LOGPREFIX) + nowString.substr(0, nowString.length()-1);
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

uint64_t UserUtils::authenticate(string username, string password, uint64_t relatedKey)
{
	if(nameMap.count(username) == 0)
	{//this account doesn't exist. end of story
		return 0;
	}

	User *user = nameMap[username];

	//need to make non const char* for scrypt library
	char *hashCStr = new char[user->getHash().length()+1];
	char *passwordCStr = new char[password.length() +1];
	std::strcpy(hashCStr, user->getHash().c_str());
	std::strcpy(passwordCStr, password.c_str());

	uint64_t sessionid = 0;
	if (libscrypt_check(hashCStr, passwordCStr) > 0)
	{
		random_device rd;
		mt19937 mt(rd());
		uniform_int_distribution<uint64_t> dist(0, (uint64_t) 9223372036854775807);
		sessionid = dist(mt);

		sessionkeyMap.erase(user->getSessionkey());
		sessionkeyMap[sessionid] = user;
		user->setSessionkey(sessionid);
	}
	delete [] hashCStr;
	delete [] passwordCStr;
	return sessionid;
}

void UserUtils::setFd(uint64_t sessionid, int fd, int which, uint64_t relatedKey)
{

	User *user = sessionkeyMap[sessionid];

	if(which == COMMAND)
	{
		user->setCommandfd(fd);
		commandfdMap.erase(fd);
		commandfdMap[fd] = user;
	}
	else if (which == MEDIA)
	{
		user->setMediafd(fd);
		mediafdMap.erase(fd);
		mediafdMap[fd] = user;
	}
}

void UserUtils::clearSession(string username, uint64_t relatedKey)
{
	if(nameMap.count(username) > 0)
	{
		User *user = nameMap[username];

		//remove session key
		sessionkeyMap.erase(user->getSessionkey());
		user->setSessionkey(0);

		//remove command and media fds
		commandfdMap.erase(user->getCommandfd());
		user->setCommandfd(0);
		mediafdMap.erase(user->getMediafd());
		user->setMediafd(0);
	}
}

bool UserUtils::verifySessionid(uint64_t sessionid, int fd, uint64_t relatedKey)
{
	if(sessionkeyMap.count(sessionid) == 0)
	{
		return false;
	}

	User *user = sessionkeyMap[sessionid];
	return user->getCommandfd() == fd;
}

string UserUtils::userFromFd(int fd, int which, uint64_t relatedKey)
{
	if(which == COMMAND)
	{
		if(commandfdMap.count(fd) > 0)
		{
			return commandfdMap[fd]->getUname();
		}
	}
	else if (which == MEDIA)
	{
		if(mediafdMap.count(fd) > 0)
		{
			return mediafdMap[fd]->getUname();
		}
	}
	return "";
}

string UserUtils::userFromSessionid(uint64_t sessionid, uint64_t relatedKey)
{
	if(sessionkeyMap.count(sessionid) > 0)
	{
		return sessionkeyMap[sessionid]->getUname();
	}

	return "";
}

int UserUtils::userFd(string user, int which, uint64_t relatedKey)
{
	if(nameMap.count(user) > 0)
	{
		User *userObj = nameMap[user];
		if(which == COMMAND)
		{
			return userObj->getCommandfd();
		}
		else if (which == MEDIA)
		{
			return userObj->getMediafd();
		}
	}
	return 0;
}

bool UserUtils::doesUserExist(string name, uint64_t relatedKey)
{
	return nameMap.count(name) > 0;
}

uint64_t UserUtils::userSessionId(string uname, uint64_t relatedKey)
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap[uname]->getSessionkey();
	}
	return 0;
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
		string nowString = string(ctime(&logTimeT));
		string logName = string(LOGPREFIX) + nowString.substr(0, nowString.length()-1);
		logfile.open(LOGFOLDER+logName);
	}
	logfile << dbl.toString() << "\n";
	logfile.flush(); // write immediately to the file
	cout << dbl.toString() << "\n";
}
