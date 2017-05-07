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


class Utils
{
	public:
		//used for parsing the configuration file: remove whitespace preceding/trailing and comments
		static std::string trim(std::string input);
		static std::string randomString(int length);
};

#endif /* UTILS_HPP_ */
