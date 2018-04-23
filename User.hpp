/*
 * User.hpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#ifndef USER_HPP_
#define USER_HPP_

#include <sodium.h>
#include <string.h>
#include <string>
#include <netinet/in.h>
#include "const.h"

class User
{
public:
	User(const std::string& cuname, unsigned char cSodiumKey[crypto_box_PUBLICKEYBYTES], const std::string& cdump);

	std::string getUname() const;
	void getSodiumPublicKey(unsigned char (&output)[crypto_box_PUBLICKEYBYTES]) const;
	std::string getSodiumPublicKeyDump() const;
	std:: string getChallenge() const;
	void setChallenge(const std::string& ch);

	uint32_t getCommandfd() const;
	void setCommandfd(uint32_t newCommandfd);

	std::string getSessionkey() const;
	void setSessionkey(const std::string& newSessionkey);

	std::string getUdpSummary() const;
	void setUdpSummary(const std::string& newSummary);

	struct sockaddr_in getUdpInfo() const;
	void setUdpInfo(struct sockaddr_in newInfo);

	ustate getUserState() const;
	void setUserState(ustate newState);

	std::string getCallWith() const;
	void setCallWith(const std::string& newOther);

	virtual ~User();

private:
	uint32_t commandfd;
	std::string uname;
	unsigned char* sodiumPublicKey[crypto_box_PUBLICKEYBYTES] = {};
	std::string sodiumPublicKeyDump;
	std::string challenge;
	std::string sessionkey;

	std::string udpSummary;
	struct sockaddr_in udpInfo;
	ustate userState;
	std::string callWith;
};

#endif /* USER_HPP_ */
