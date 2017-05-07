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

using namespace std;

class User
{
public:
	User(string cunmae, RSA *ckey);
	string getUname();
	RSA* getPublicKey();
	string getChallenge();
	void setChallenge(string ch);

	uint32_t getCommandfd();
	void setCommandfd(uint32_t newCommandfd);

	uint32_t getMediafd();
	void setMediafd(uint32_t newMediafd);

	uint64_t getSessionkey();
	void setSessionkey(uint64_t newSessionkey);

	virtual ~User();

private:
	uint32_t commandfd;
	uint32_t mediafd;
	string uname;
	RSA *publicKey;
	string challenge;
	uint64_t sessionkey;
};

#endif /* USER_HPP_ */
