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

class UserUtils
{
public:
	static UserUtils* getInstance();

	bool getSodiumPublicKey(const std::string& username, unsigned char (&output)[crypto_box_PUBLICKEYBYTES]) const;
	std::string getSodiumKeyDump(const std::string &uname) const;

	std::string getChallenge(std::string const &username) const;
	void setChallenge(std::string const &username, std::string challenge);

	std::string userFromSessionKey(std::string const &sessionkey) const;
	std::string getSessionKey(std::string const &uname) const;
	void setSessionKey(std::string const &username, std::string sessionkey);
	bool verifySessionKey(std::string const &sessionkey, int fd) const;
	void clearSession(std::string const &username);

	std::string userFromCommandFd(int fd) const;
	int getCommandFd(std::string const &user) const;
	void setCommandFd(std::string const &sessionkey, int fd);

	std::string userFromUdpSummary(std::string const &summary) const;
	void setUdpSummary(std::string const &sessionkey, std::string summary);
	struct sockaddr_in getUdpInfo(std::string const &uname) const;
	void setUdpInfo(std::string const &sessionkey, struct sockaddr_in info);
	void clearUdpInfo(std::string const &uname);

	ustate getUserState(std::string const &uname) const;
	void setUserState(std::string const &uname, ustate newstate);

	std::string getCallWith(std::string const &uname) const;
	void setCallPair(std::string uname, std::string newOther);
	void removeCallPair(std::string const &uname);

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
};

#endif /* USERUTILS_HPP_ */
