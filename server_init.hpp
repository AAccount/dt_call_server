/*
 * server_init.h
 *
 *  Created on: May 2, 2017
 *      Author: Daniel
 */

#ifndef SERVER_INIT_HPP_
#define SERVER_INIT_HPP_
#include <sstream>
#include <iostream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "const.h"
#include "Log.hpp"
#include "UserUtils.hpp"

void readServerConfig(int &cmdPort, int &mediaPort, std::string &publicKeyFile, std::string &privateKeyFile, std::string &ciphers, std::string &dhfile, UserUtils *userUtils);
SSL_CTX* setupOpenSSL(std::string ciphers, std::string privateKeyFile, std::string publicKeyFile, std::string dhfile, UserUtils *userUtils);
void setupListeningSocket(int type, struct timeval *timeout, int *fd, struct sockaddr_in *info, int port, UserUtils *userUtils);

#endif /* SERVER_INIT_HPP_ */
