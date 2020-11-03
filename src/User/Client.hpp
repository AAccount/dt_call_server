/*
 * Client.hpp
 *
 *  Created on: Oct 13, 2018
 *      Author: Daniel
 */
#ifndef CLIENT_HPP_
#define CLIENT_HPP_
#include <memory>

#include <sodium.h>
#include <string.h>

class Client
{
public:
	Client();
	virtual ~Client();

	bool isNew() const;
	void hasBeenSeen();
	const std::unique_ptr<unsigned char[]>& getSymmetricKey() const;

private:
	std::unique_ptr<unsigned char[]> symmetricKey;;
	bool newClient;
};

#endif /* CLIENT_HPP_ */
