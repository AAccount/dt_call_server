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

class Utils
{
	public:
		//used for parsing the configuration file: remove whitespace preceding/trailing and comments
		static std::string trim(std::string const &input);
		static std::string randomString(int length);

		//turn unsigned char array into/out of string of #s
		static std::string stringify(unsigned char* bytes, int length);
		static void destringify(const std::string &input, unsigned char* output);

		//verify basic key file formatting based on header and string length
		static bool checkSodiumPublic(const std::string& input);
		static bool checkSodiumPrivate(const std::string& input);
		static std::string dumpSmallFile(const std::string& path);

};

#endif /* UTILS_HPP_ */
