/*
 * User.cpp
 *
 *  Created on: Oct 30, 2020
 *      Author: Daniel
 */
#ifndef COMMAND_UTILS_
#define COMMAND_UTILS_

#include <string>
#include <vector>
#include <sys/time.h>

#include "../Log/Log.hpp"

namespace CommandUtils
{
	//check the timestamp string to see if it's within the limits
	bool checkTimestamp(const std::string& tsString, Log::TAG tag, const std::string& errorMessage, const std::string& user, const std::string& ip);

	//check to see if the bytes in the buffer are legitimate ascii characters of interest and doesn't contain any junk
	bool legitimateAscii(unsigned char* buffer, int length);

	//parse incoming server commands (split the incoming command string by the | character)
	std::vector<std::string> parse(unsigned char command[]);

	std::string unixTs();
};
#endif