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
#include <sodium.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "const.h"
#include "Log.hpp"
#include "UserUtils.hpp"

void readServerConfig(int &cmdPort, int &mediaPort, std::string &publicKeyFile, std::string &privateKeyFile, std::string &ciphers, std::string &dhfile, std::string &sodiumPublic, std::string &sodium_private, Logger* logger);
SSL_CTX* setupOpenSSL(std::string const &ciphers, std::string const &privateKeyFile, std::string const &publicKeyFile, std::string const &dhfile);
void setupListeningSocket(int type, struct timeval* timeout, int* fd, struct sockaddr_in* info, int port);

#endif /* SERVER_INIT_HPP_ */
