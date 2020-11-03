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

#include <sodium.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "const.h"
#include "Log/Log.hpp"
#include "User/UserUtils.hpp"
#include "sodium_utils.hpp"
#include "ServerCommand/ServerCommands.hpp"
#include "ServerCommand/CommandContext.hpp"

void initDtOperator(int argc, char* argv[], int& commandFd, int& mediaFd, const std::unique_ptr<unsigned char[]>& publicKey, const std::unique_ptr<unsigned char[]>& privateKey);
void readServerConfig(const std::string& settingsLocation, int &cmdPort, int &mediaPort, std::string &sodiumPublic, std::string &sodium_private, Logger* logger);
void setupListeningSocket(int type, struct timeval* timeout, int* fd, struct sockaddr_in* info, int port);
void parseArgv(int argc, char* argv[], std::string& settingsLocation, std::string& logLocation);
void ignoreSigPipe();
int setupCommandFd(int cmdPort);
int setupMediaFd(int mediaPort, Logger* logger);
void initializeSodiumKeys(Logger* logger, std::string& publicString, std::string& privateString, const std::unique_ptr<unsigned char[]>& publicKey, const std::unique_ptr<unsigned char[]>& privateKey);

#endif /* SERVER_INIT_HPP_ */
