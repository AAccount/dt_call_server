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

class Utils
{
	public:
		//get the time now in milliseconds
		static uint64_t millisNow();

		//used for parsing the configuration file: remove whitespace preceding/trailing and comments
		static std::string trim(std::string input);
};

#endif /* UTILS_HPP_ */
