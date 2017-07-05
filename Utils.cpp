/*
 * Utils.cpp
 *
 *  Created on: Aug 14, 2016
 *      Author: Daniel
 */

#include "Utils.hpp"
#include <time.h>
#include <stdint.h>

//make the random generator components once and reuse
std::uniform_int_distribution<int> Utils::dist(0,61);
std::mt19937 Utils::mt(std::random_device{}());

//https://stackoverflow.com/questions/1798112/removing-leading-and-trailing-spaces-from-a-string
std::string Utils::trim (std::string str)
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

//https://stackoverflow.com/questions/19665818/generate-random-numbers-using-c11-random-library
std::string Utils::randomString(int length)
{
	const std::string alphanum[] =
    {"0","1","2","3","4",
    "5","6","7","8","9",
    "A","B","C","D","E","F",
    "G","H","I","J","K",
    "L","M","N","O","P",
    "Q","R","S","T","U",
    "V","W","X","Y","Z",
    "a","b","c","d","e","f",
    "g","h","i","j","k",
    "l","m","n","o","p",
    "q","r","s","t","u",
    "v","w","x","y","z"
    };

	std::string randomized = "";
	for(int i=0; i<length; i++)
	{
		int index = dist(mt);
		std::string character = alphanum[index];
		randomized = randomized + character;
	}
	return randomized;
}
