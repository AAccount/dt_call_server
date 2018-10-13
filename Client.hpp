/*
 * Client.hpp
 *
 *  Created on: Oct 13, 2018
 *      Author: Daniel
 */
#ifndef CLIENT_HPP_
#define CLIENT_HPP_
#include <sodium.h>
#include <string.h>

class Client
{
public:
	Client();
	virtual ~Client();

	bool isNew() const;
	void setSeen();
	const unsigned char* getSymmetricKey() const;

private:
	unsigned char symmetricKey[crypto_secretbox_KEYBYTES] = {};
	bool newClient;
};

#endif /* CLIENT_HPP_ */
