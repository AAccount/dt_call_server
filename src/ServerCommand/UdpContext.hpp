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
	UdpContext(Logger* clogger, UserUtils* cuserUtils, const std::unique_ptr<unsigned char[]>& cpublic, const std::unique_ptr<unsigned char[]>& cprivate, const struct sockaddr_in& csender, int csenderLength, int cmediaFd, std::string& cuser);
	UdpContext(Logger* clogger, UserUtils* cuserUtils, const std::unique_ptr<unsigned char[]>& cpublic, const std::unique_ptr<unsigned char[]>& cprivate, const struct sockaddr_in& csender, int csenderLength, int cmediaFd, std::string& cuser, std::string& cregistrationString, std::vector<std::string>& cregistrationContents);
	virtual ~UdpContext();

	Logger* getLogger() const;
	UserUtils* getUserUtils() const;
	const std::unique_ptr<unsigned char[]>& getPublicKey() const;
	const std::unique_ptr<unsigned char[]>& getPrivateKey() const;
	const struct sockaddr_in& getSender() const;
 	int getSenderLength() const;
	int getMediaFd() const;
	std::string getUser() const;
	std::string getRegistrationString() const;
	std::vector<std::string> getRegistrationContents() const;

	void setUser(const std::string& user);
	void setRegistrationString(const std::string& reg);
	void setRegistrationContents(const std::vector<std::string>& contents);

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