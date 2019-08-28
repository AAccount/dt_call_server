/*
 * User.cpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#include "User.hpp"

User::User(const std::string& cuname, unsigned char cnakey[crypto_box_PUBLICKEYBYTES], const std::string& cdump) :
	uname(cuname),
	sodiumPublicKeyDump(cdump),
	commandfd(0),
	sessionkey(""),
	challenge(""),
	udpSummary(""),
	userState(NONE),
	callWith("")
{
	memcpy(sodiumPublicKey, cnakey, crypto_box_PUBLICKEYBYTES);
	memset(&udpInfo, 0, sizeof(struct sockaddr_in));
}

User::~User()
{
}

std::string User::getChallenge() const
{
	return challenge;
}

void User::setChallenge(const std::string& pchallenge)
{
	challenge = pchallenge;
}

std::string User::getUname() const
{
	return uname;
}

void User::getSodiumPublicKey(unsigned char (&output)[crypto_box_PUBLICKEYBYTES]) const
{
	memcpy(output, sodiumPublicKey, crypto_box_PUBLICKEYBYTES);
}

std::string User::getSodiumPublicKeyDump() const
{
	return sodiumPublicKeyDump;
}

uint32_t User::getCommandfd() const
{
	return commandfd;
}

void User::setCommandfd(uint32_t newCommandfd)
{

	commandfd = newCommandfd;
}

std::string User::getUdpSummary() const
{
	return udpSummary;
}

void User::setUdpSummary(const std::string& newSummary)
{
	udpSummary = newSummary;
}

struct sockaddr_in User::getUdpInfo() const
{
	return udpInfo;
}

void User::setUdpInfo(struct sockaddr_in newInfo)
{
	udpInfo = newInfo;
}

ustate User::getUserState() const
{
	return userState;
}

void User::setUserState(ustate newState)
{
	userState = newState;
}

std::string User::getSessionkey() const
{
	return sessionkey;
}

void User::setSessionkey(const std::string& newSessionkey)
{
	sessionkey = newSessionkey;
}

std::string User::getCallWith() const
{
	return callWith;
}
void User::setCallWith(const std::string& newOther)
{
	callWith = newOther;
}
