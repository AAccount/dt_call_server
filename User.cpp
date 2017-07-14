/*
 * User.cpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#include "User.hpp"

User::User(std::string cuname, RSA *ckey, std::string cdump)
{
	uname = cuname;
	publicKey = ckey;
	publicKeyDump = cdump;
	commandfd = 0;
	sessionkey = "";
	challenge = "";

	udpSummary = "";
	userState = NONE;
	callWith = "";
	//ok not to initialize the struct since the summary is 0. with a 0 summary nobody will look at the struct
}

User::~User()
{
	RSA_free(publicKey);
}

std::string User::getChallenge()
{
	return challenge;
}

void User::setChallenge(std::string pchallenge)
{
	challenge = pchallenge;
}

std::string User::getUname()
{
	return uname;
}

RSA* User::getPublicKey()
{
	return publicKey;
}

std::string User::getPublicKeyDump()
{
	return publicKeyDump;
}

uint32_t User::getCommandfd()
{
	return commandfd;
}

void User::setCommandfd(uint32_t newCommandfd)
{

	commandfd = newCommandfd;
}

std::string User::getUdpSummary()
{
	return udpSummary;
}

void User::setUdpSummary(std::string newSummary)
{
	udpSummary = newSummary;
}

struct sockaddr_in User::getUdpInfo()
{
	return udpInfo;
}

void User::setUdpInfo(struct sockaddr_in newInfo)
{
	udpInfo = newInfo;
}

ustate User::getUserState()
{
	return userState;
}

void User::setUserState(ustate newState)
{
	userState = newState;
}

std::string User::getSessionkey()
{
	return sessionkey;
}

void User::setSessionkey(std::string newSessionkey)
{
	sessionkey = newSessionkey;
}

std::string User::getCallWith()
{
	return callWith;
}
void User::setCallWith(std::string newOther)
{
	callWith = newOther;
}
