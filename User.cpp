/*
 * User.cpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#include "User.hpp"

using namespace std;

User::User(string cuname, string chash)
{
	uname = cuname;
	hash = chash;
	commandfd = 0;
	mediafd = 0;
	sessionkey = 0;
}

User::~User()
{
	// TODO Auto-generated destructor stub
}

string User::getUname()
{
	return uname;
}

string User::getHash()
{
	return hash;
}


uint32_t User::getCommandfd()
{
	return commandfd;
}

void User::setCommandfd(uint32_t newCommandfd)
{
	if(newCommandfd > 4)
	{
		commandfd = newCommandfd;
	}
}

uint32_t User::getMediafd()
{
	return mediafd;
}

void User::setMediafd(uint32_t newMediafd)
{
	if(newMediafd > 4)
	{
		mediafd = newMediafd;
	}
}

uint64_t User::getSessionkey()
{
	return sessionkey;
}

void User::setSessionkey(uint64_t newSessionkey)
{
	sessionkey = newSessionkey;
}
