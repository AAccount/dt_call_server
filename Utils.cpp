/*
 * Utils.cpp
 *
 *  Created on: Aug 14, 2016
 *      Author: Daniel
 */

#include "Utils.hpp"
#include <time.h>
#include <stdint.h>

//https://stackoverflow.com/questions/1798112/removing-leading-and-trailing-spaces-from-a-string
std::string trim (std::string str)
{//
	//nothing to trim in a blank string
	if(str.length() == 0)
	{
		return str;
	}

	size_t beginning = str.find_first_not_of(" \r\n\t");

	//if there is a comment then start looking BEFORE the comment otherwise find_last_not_of
	//will "OK" the comment characters and fail to trim
	size_t comment = str.find('#');
	size_t ending;
	if(comment != std::string::npos)
	{
		ending = str.find_last_not_of(" #\r\n\t", comment); //strip off the comment
	}
	else
	{
		ending = str.find_last_not_of(" #\r\n\t"); //strip off the comment
	}
	size_t range = ending-beginning+1;
	return str.substr(beginning, range);
}
