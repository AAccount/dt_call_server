/*
 * User.hpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#ifndef USER_HPP_
#define USER_HPP_

#include <string>
#include <openssl/pem.h>
#include <netinet/in.h>
#include "const.h"

class User
{
public:
	User(std::string cuname, RSA *ckey, std::string cdump);
	std::string getUname() const;
	RSA* getPublicKey() const;
	std::string getPublicKeyDump() const;
	std:: string getChallenge() const;
	void setChallenge(std::string ch);

	uint32_t getCommandfd() const;
	void setCommandfd(uint32_t newCommandfd);

	std::string getSessionkey() const;
	void setSessionkey(std::string newSessionkey);

	std::string getUdpSummary() const;
	void setUdpSummary(std::string newSummary);

	struct sockaddr_in getUdpInfo() const;
	void setUdpInfo(struct sockaddr_in newInfo);

	ustate getUserState() const;
	void setUserState(ustate newState);

	std::string getCallWith() const;
	void setCallWith(std::string newOther);

	virtual ~User();

private:
	uint32_t commandfd;
	std::string uname;
	RSA *publicKey;
	std::string publicKeyDump;
	std::string challenge;
	std::string sessionkey;

	std::string udpSummary;
	struct sockaddr_in udpInfo;
	ustate userState;
	std::string callWith;
};

#endif /* USER_HPP_ */
