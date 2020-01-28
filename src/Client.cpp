/*
 * Client.cpp
 *
 *  Created on: Oct 13, 2018
 *      Author: Daniel
 */

#include "Client.hpp"

Client::Client() :
newClient(true),
symmetricKey(std::make_unique<unsigned char[]>(crypto_secretbox_KEYBYTES))
{
	randombytes_buf(symmetricKey.get(), crypto_secretbox_KEYBYTES);
}

Client::~Client()
{
	//remove the old key from memory??
	randombytes_buf(symmetricKey.get(), crypto_secretbox_KEYBYTES);
}

bool Client::isNew() const
{
	return newClient;
}

void Client::hasBeenSeen()
{
	newClient = false;
}

const std::unique_ptr<unsigned char[]>& Client::getSymmetricKey() const
{
	return symmetricKey;
}
