/*
 * Utils.hpp
 *
 *  Created on: Aug 14, 2016
 *      Author: Daniel
 *
 *  Common stuff used by multiple files
 */

#ifndef UTILS_HPP_
#define UTILS_HPP_
#include <stdint.h>
#include <string>
#include <random>
#include <iostream>
#include <sstream>
#include <fstream>
#include <time.h>
#include <stdint.h>
#include <sodium.h>
#include "const.h"

namespace Utils
{
	//used for parsing the configuration file: remove whitespace preceding/trailing and comments
	std::string trim(std::string const &input);

	//verify basic key file formatting based on header and string length
	std::string dumpSmallFile(const std::string& path);

};

#endif /* UTILS_HPP_ */
