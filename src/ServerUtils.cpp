/*
 * Utils.cpp
 *
 *  Created on: Aug 14, 2016
 *      Author: Daniel
 */

#include "ServerUtils.hpp"

//https://stackoverflow.com/questions/1798112/removing-leading-and-trailing-spaces-from-a-string
std::string ServerUtils::trim (std::string const &input)
{//
	//nothing to trim in a blank string
	if(input.length() == 0)
	{
		return input;
	}

	size_t beginning = input.find_first_not_of(" \r\n\t");

	//if there is a comment then start looking BEFORE the comment otherwise find_last_not_of
	//will "OK" the comment characters and fail to trim
	size_t comment = input.find('#');
	size_t ending;
	if(comment != std::string::npos)
	{
		ending = input.find_last_not_of(" #\r\n\t", comment); //strip off the comment
	}
	else
	{
		ending = input.find_last_not_of(" #\r\n\t"); //strip off the comment
	}
	size_t range = ending-beginning+1;
	return input.substr(beginning, range);
}

std::string ServerUtils::dumpSmallFile(const std::string& path)
{
	std::ifstream fileStream(path);
	std::stringstream stringStream;
	stringStream << fileStream.rdbuf();
	fileStream.close();
	return stringStream.str();
}

std::string ServerUtils::printErrno()
{
	return "(" + std::to_string(errno) + ") " + std::string(strerror(errno));
}

