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
	User(std::string cunmae, RSA *ckey, std::string cdump);
	std::string getUname();
	RSA* getPublicKey();
	std::string getPublicKeyDump();
	std:: string getChallenge();
	void setChallenge(std::string ch);

	uint32_t getCommandfd();
	void setCommandfd(uint32_t newCommandfd);

	std::string getSessionkey();
	void setSessionkey(std::string newSessionkey);

	std::string getUdpSummary();
	void setUdpSummary(std::string newSummary);

	struct sockaddr_in getUdpInfo();
	void setUdpInfo(struct sockaddr_in newInfo);

	ustate getUserState();
	void setUserState(ustate newState);

	std::string getCallWith();
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
