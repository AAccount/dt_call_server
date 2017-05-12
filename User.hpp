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

class User
{
public:
	User(std::string cunmae, RSA *ckey);
	std::string getUname();
	RSA* getPublicKey();
	std:: string getChallenge();
	void setChallenge(std::string ch);

	uint32_t getCommandfd();
	void setCommandfd(uint32_t newCommandfd);

	uint32_t getMediafd();
	void setMediafd(uint32_t newMediafd);

	std::string getSessionkey();
	void setSessionkey(std::string newSessionkey);

	virtual ~User();

private:
	uint32_t commandfd;
	uint32_t mediafd;
	std::string uname;
	RSA *publicKey;
	std::string challenge;
	std::string sessionkey;
};

#endif /* USER_HPP_ */
