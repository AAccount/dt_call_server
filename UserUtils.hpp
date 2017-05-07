/*
 * UserUtils.hpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
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

#include "Utils.hpp"
#include "const.h"
#include "Log.hpp"
#include "User.hpp"

using namespace std;

class UserUtils
{
public:
	static UserUtils* getInstance();

	//db set/write functions
	RSA *getUserPublicKey(string username);
	string getUserChallenge(string username);
	void setUserChallenge(string username, string challenge);
	void setUserSession(string username, uint64_t sessionid);
	void setFd(uint64_t sessionid, int fd, int which);
	void clearSession(string username);

	//db verification functions
	bool verifySessionid(uint64_t sessionid, int fd);
	bool doesUserExist(string name);

	//db lookup functions
	string userFromFd(int fd, int which);
	string userFromSessionid(uint64_t sessionid);
	int userFd(string user, int which);
	uint64_t userSessionId(string uname);
	void killInstance();

	//log related functions
	void insertLog(Log l);

private:
	UserUtils();
	~UserUtils();
	static UserUtils *instance;

	//various hash maps to lookup the user by
	//	a crude in memory db
	unordered_map<string, User*> nameMap;
	unordered_map<uint32_t, User*> commandfdMap;
	unordered_map<uint32_t, User*> mediafdMap;
	unordered_map<uint64_t, User*> sessionkeyMap;

	//output log (changed every 24 hours)
	ofstream logfile;
	time_t logTimeT;
};

#endif /* USERUTILS_HPP_ */
