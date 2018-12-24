/*
 * UserUtils.hpp
 *
 *  Created on: December 8, 2015
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
#include <queue>

#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <pthread.h>

#include "Utils.hpp"
#include "const.h"
#include "Log.hpp"
#include "User.hpp"
#include "Logger.hpp"
#include "sodium_utils.hpp"
#include "stringify.hpp"

class UserUtils
{
public:
	static UserUtils* getInstance();

	bool getSodiumPublicKey(const std::string& username, unsigned char (&output)[crypto_box_PUBLICKEYBYTES]) const;
	std::string getSodiumKeyDump(const std::string& uname) const;

	std::string getChallenge(const std::string& username) const;
	void setChallenge(const std::string& username, const std::string& challenge);

	std::string userFromSessionKey(const std::string& sessionkey) const;
	std::string getSessionKey(const std::string& uname) const;
	void setSessionKey(const std::string& username, const std::string& sessionkey);
	bool verifySessionKey(const std::string& sessionkey, int fd) const;
	void clearSession(const std::string& username, bool keepudp);

	std::string userFromCommandFd(int fd) const;
	int getCommandFd(const std::string& user) const;
	void setCommandFd(const std::string& sessionkey, int fd);

	std::string userFromUdpSummary(const std::string& summary) const;
	void setUdpSummary(const std::string& sessionkey, const std::string& summary);
	struct sockaddr_in getUdpInfo(const std::string& uname) const;
	void setUdpInfo(const std::string& sessionkey, struct sockaddr_in info);
	void clearUdpInfo(const std::string& uname);

	ustate getUserState(const std::string& uname) const;
	void setUserState(const std::string& uname, ustate newstate);

	std::string getCallWith(const std::string& uname) const;
	void setCallPair(const std::string& uname, const std::string& newOther);
	void removeCallPair(const std::string& uname);

	void killInstance();

private:
	UserUtils();
	~UserUtils();
	static UserUtils* instance;

	//various hash maps to lookup the user by.
	//	a crude in memory db.
	std::unordered_map<std::string, User*> nameMap;
	std::unordered_map<uint32_t, User*> commandfdMap;
	std::unordered_map<std::string, User*> sessionkeyMap;
	std::unordered_map<std::string, User*> udpMap;

	//never need to copy
	UserUtils(const UserUtils&) = delete;
};

#endif /* USERUTILS_HPP_ */
