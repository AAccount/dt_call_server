/*
 * UserUtils.cpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#include "const.h"
#include "UserUtils.hpp"

//static members
UserUtils* UserUtils::instance;
time_t UserUtils::logTimeT;
std::ofstream *UserUtils::logfile;
pthread_t UserUtils::diskThread;
pthread_mutex_t UserUtils::qMutex;
pthread_cond_t UserUtils::wakeup;
std::queue<Log> UserUtils::backlog;

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
		std::string name, publicKey, publicKeyDump;
		std::stringstream ss(line);
		getline(ss, name, '>');
		getline(ss, publicKey, '>');

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
	//(ok to stall the program here as you need the log initialized before you can do anything)
	logTimeT = time(NULL);
	std::string nowString = std::string(ctime(&logTimeT));
	std::string logName = LOGPREFIX() + nowString.substr(0, nowString.length()-1);
	logfile = new std::ofstream(LOGFOLDER()+logName);

	//keep disk IO on its own thread. don't know what kind of disk you'll get
	//don't let a slow disk stall the whole program just for logging.
	pthread_mutex_init(&qMutex, NULL);
	pthread_cond_init(&wakeup, NULL);
	if (pthread_create(&diskThread, NULL, diskRw, NULL) != 0)
	{
		std::string error = "cannot create the disk rw thread (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		exit(1);
	}
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
	delete logfile;
}

RSA* UserUtils::getPublicKey(std::string username)
{
	if(nameMap.count(username) > 0)
	{
		return nameMap[username]->getPublicKey();
	}
	return NULL;
}

std::string UserUtils::getChallenge(std::string const &username)
{
	if(nameMap.count(username) > 0)
	{
		return nameMap[username]->getChallenge();
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
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
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
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
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
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
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
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

bool UserUtils::verifySessionKey(std::string const &sessionid, int fd)
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

std::string UserUtils::userFromSessionKey(std::string const &sessionid)
{
	if(sessionkeyMap.count(sessionid) > 0)
	{
		return sessionkeyMap[sessionid]->getUname();
	}
	std::string error = "no user matches the session id supplied";
	insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	return "";
}

int UserUtils::getCommandFd(std::string const &user)
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

std::string UserUtils::getSessionKey(std::string const &uname)
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap[uname]->getSessionkey();
	}
	std::string error = "tried to get a session key for somebody that doesn't exist: " + uname;
	insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	return "";
}

std::string UserUtils::userFromUdpSummary(std::string const &summary)
{
	if(udpMap.count(summary) > 0)
	{
		return udpMap[summary]->getUname();
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
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
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
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

struct sockaddr_in UserUtils::getUdpInfo(std::string const &uname)
{
	return nameMap[uname]->getUdpInfo();
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
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

ustate UserUtils::getUserState(std::string const &uname)
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap[uname]->getUserState();
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
		insertLog(Log(TAG_USERUTILS, error, SELF, ERRORLOG, SELFIP));
	}
}

std::string UserUtils::getPublicKeyDump(std::string const &uname)
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap[uname]->getPublicKeyDump();
	}
	return "";
}

std::string UserUtils::getCallWith(std::string const &uname)
{
	if(nameMap.count(uname) > 0)
	{
		return nameMap[uname]->getCallWith();
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

void* UserUtils::diskRw(void *ignored)
{
	while(true)
	{
		pthread_mutex_lock(&qMutex);
			bool empty = backlog.empty();
		pthread_mutex_unlock(&qMutex);

		while(!empty)
		{
			//get the next log item
			pthread_mutex_lock(&qMutex);
				Log log = backlog.front();
				backlog.pop();
				empty = backlog.empty();
			pthread_mutex_unlock(&qMutex);

			//figure out if the current log is over 1 day old
			time_t now = time(NULL);
			if((now - logTimeT) > 60*60*24)
			{//if the log is too old, close it and start another one
				logfile->close();
				logTimeT = now;
				std::string nowString = std::string(ctime(&logTimeT));
				std::string logName = LOGPREFIX() + nowString.substr(0, nowString.length()-1);
				logfile->open(LOGFOLDER()+logName);
			}
			*(logfile) << log << "\n";
			logfile->flush(); // write immediately to the file

			if(log.getType() == ERRORLOG)
			{//make errors dead obvious when testing
				std::cerr << log << "\n";
			}
			else
			{
				std::cout << log << "\n";
			}
		}

		//no more logs to write? wait until there is one
#ifdef VERBOSE
		std::cout << "DISK RW: nothing to write\n";
#endif
		while(backlog.empty())
		{
			pthread_cond_wait(&wakeup, &qMutex);
#ifdef VERBOSE
			std::cout << "DISK RW: woken up to write\n";
#endif
		}
		pthread_mutex_unlock(&qMutex);
	}
}

void UserUtils::insertLog(Log dbl)
{
	//put a new log in the backlog
	pthread_mutex_lock(&qMutex);
		backlog.push(dbl);
	pthread_mutex_unlock(&qMutex);

	pthread_cond_signal(&wakeup);
}
