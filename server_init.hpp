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

#include "const.h"
#include "Log.hpp"
#include "UserUtils.hpp"

void readServerConfig(int *cmdPort, int *mediaPort, std::string *publicKeyFile, std::string *privateKeyFile, std::string *ciphers, std::string *dhfile, UserUtils *userUtils, uint64_t initkey);


#endif /* SERVER_INIT_HPP_ */
