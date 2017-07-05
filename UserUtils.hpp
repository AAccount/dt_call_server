/*
 * UserUtils.hpp
 *
 *  Created on: 2nd half December 2015
 *      Author: Daniel
 *      Rebranded from DbUtils
 */

#ifndef USERUTILS_HPP_
#define USERUTILS_HPP_

#include <unordered_map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctime>
#include <string>
#include <cstring>
#include <random>

#include <stdio.h>

#include <openssl/pem.h>
#include <netinet/in.h>

#include "Utils.hpp"
#include "const.h"
#include "Log.hpp"
#include "User.hpp"


class UserUtils
{
public:
	static UserUtils* getInstance();

	RSA *getPublicKey(std::string username);
	std::string getPublicKeyDump(std::string uname);

	std::string getChallenge(std::string username);
	void setChallenge(std::string username, std::string challenge);

	std::string userFromSessionKey(std::string sessionkey);
	std::string getSessionKey(std::string uname);
	void setSessionKey(std::string username, std::string sessionkey);
	bool verifySessionKey(std::string sessionkey, int fd);
	void clearSession(std::string username);

	std::string userFromCommandFd(int fd);
	int getCommandFd(std::string user);
	void setCommandFd(std::string sessionkey, int fd);

	std::string userFromUdpSummary(std::string summary);
	void setUdpSummary(std::string sessionkey, std::string summary);
	struct sockaddr_in getUdpInfo(std::string uname);
	void setUdpInfo(std::string sessionkey, struct sockaddr_in info);
	void clearUdpInfo(std::string uname);

	ustate getUserState(std::string uname);
	void setUserState(std::string uname, ustate newstate);

	void insertLog(Log l);
	void killInstance();

private:
	UserUtils();
	~UserUtils();
	static UserUtils *instance;

	//various hash maps to lookup the user by.
	//	a crude in memory db.
	std::unordered_map<std::string, User*> nameMap;
	std::unordered_map<uint32_t, User*> commandfdMap;
	std::unordered_map<std::string, User*> sessionkeyMap;
	std::unordered_map<std::string, User*> udpMap;

	//output log (changed every 24 hours)
	std::ofstream logfile;
	time_t logTimeT;
};

#endif /* USERUTILS_HPP_ */
