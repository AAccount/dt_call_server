/*
 * Client.cpp
 *
 *  Created on: Oct 13, 2018
 *      Author: Daniel
 */

#include "Client.hpp"

Client::Client() :
	newClient(true)
{
	randombytes_buf(symmetricKey, crypto_secretbox_KEYBYTES);
}

Client::~Client()
{
	//remove the old key from memory??
	randombytes_buf(symmetricKey, crypto_secretbox_KEYBYTES);
}

bool Client::isNew() const
{
	return newClient;
}

void Client::setSeen()
{
	newClient = false;
}

const unsigned char* Client::getSymmetricKey() const
{
	return symmetricKey;
}
