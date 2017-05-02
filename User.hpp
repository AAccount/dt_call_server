/*
 * User.hpp
 *
 *  Created on: May 1, 2017
 *      Author: Daniel
 */

#ifndef USER_HPP_
#define USER_HPP_

#include <string>

using namespace std;

class User
{
public:
	User(string cunmae, string chash);
	string getUname();
	string getHash();

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
	string hash;
	uint64_t sessionkey;
};

#endif /* USER_HPP_ */
