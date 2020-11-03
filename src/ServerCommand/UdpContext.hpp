/*
 * CommandContext.hpp
 *
 *  Created on: Nov 1, 2020
 *      Author: Daniel
 */

#ifndef UDP_CONTEXT_
#define UDP_CONTEXT_

#include <string>
#include <vector>

#include "../Log/Logger.hpp"
#include "../User/UserUtils.hpp"

class UdpContext
{
public:
	UdpContext(Logger* clogger, UserUtils* cuserUtils, const std::unique_ptr<unsigned char[]>& cpublic, const std::unique_ptr<unsigned char[]>& cprivate, struct sockaddr_in& csender, int csenderLength, int cmediaFd, std::string& cuser);
	UdpContext(Logger* clogger, UserUtils* cuserUtils, const std::unique_ptr<unsigned char[]>& cpublic, const std::unique_ptr<unsigned char[]>& cprivate, struct sockaddr_in& csender, int csenderLength, int cmediaFd, std::string& cuser, std::string& cregistrationString, std::vector<std::string>& cregistrationContents);
	virtual ~UdpContext();

	Logger* getLogger();
	UserUtils* getUserUtils();
	const std::unique_ptr<unsigned char[]>& getPublicKey();
	const std::unique_ptr<unsigned char[]>& getPrivateKey();
	const struct sockaddr_in& getSender();
 	int getSenderLength();
	int getMediaFd();
	std::string getUser();
	std::string getRegistrationString();
	std::vector<std::string> getRegistrationContents();

	void setUser(std::string user);
	void setRegistrationString(std::string& reg);
	void setRegistrationContents(std::vector<std::string>& contents);

private:
	Logger* logger;
	UserUtils* userUtils;
	const std::unique_ptr<unsigned char[]>& publicKey;
	const std::unique_ptr<unsigned char[]>& privateKey;
	const struct sockaddr_in& sender;
 	const int senderLength;
	const int mediaFd;

	std::string user;
	std::string registrationString;
	std::vector<std::string> registrationContents;
};

#endif