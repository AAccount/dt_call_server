/*
 * User.cpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#include "User.hpp"

using namespace std;

User::User(string cuname, RSA *ckey)
{
	uname = cuname;
	publicKey = ckey;
	commandfd = 0;
	mediafd = 0;
	sessionkey = "";
	challenge = "";
}

User::~User()
{
	RSA_free(publicKey);
}

string User::getChallenge()
{
	return challenge;
}

void User::setChallenge(string pchallenge)
{
	challenge = pchallenge;
}

string User::getUname()
{
	return uname;
}

RSA* User::getPublicKey()
{
	return publicKey;
}


uint32_t User::getCommandfd()
{
	return commandfd;
}

void User::setCommandfd(uint32_t newCommandfd)
{

	commandfd = newCommandfd;
}

uint32_t User::getMediafd()
{
	return mediafd;
}

void User::setMediafd(uint32_t newMediafd)
{

	mediafd = newMediafd;
}

string User::getSessionkey()
{
	return sessionkey;
}

void User::setSessionkey(string newSessionkey)
{
	sessionkey = newSessionkey;
}
