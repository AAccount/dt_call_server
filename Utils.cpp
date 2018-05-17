/*
 * Utils.cpp
 *
 *  Created on: Aug 14, 2016
 *      Author: Daniel
 */

#include "Utils.hpp"

//https://stackoverflow.com/questions/1798112/removing-leading-and-trailing-spaces-from-a-string
std::string Utils::trim (std::string const &input)
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

//https://stackoverflow.com/questions/19665818/generate-random-numbers-using-c11-random-library
std::string Utils::randomString(int length)
{
	if(sodium_init() == -1)
	{
		exit(1); //any signs of sodium failure makes this program useless
	}

	int alphanumLength = 62;
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
		int index = randombytes_uniform(alphanumLength);
		std::string character = alphanum[index];
		randomized = randomized + character;
	}
	return randomized;
}

std::string Utils::stringify(unsigned char* bytes, int length)
{
	std::string result = "";
	for(int i=0; i<length; i++)
	{
		std::string number = std::to_string(bytes[i]);
		if(bytes[i] < 10)
		{//for 1,2,3 to keep everything as 3 digit #s make it 001, 002 etc
			number = "00" + number;
		}
		else if (bytes[i] < 100)
		{//for 10,11,12 make it 010,011,012
			number = "0" + number;
		}
		result = result + number;
	}
	return result;
}

void Utils::destringify(const std::string &input, unsigned char* output)
{
	for(int i=0; i<input.length(); i = i+3)
	{
		std::string digit = input.substr(i, 3);
		output[i/3] = (unsigned char)std::stoi(digit);
	}
}

bool Utils::checkSodiumPrivate(const std::string& input)
{
	std::string privateHeader = SODIUM_PRIVATE_HEADER();
	bool hasHeader = (input.length() > 0 && input.substr(0, privateHeader.length()) == privateHeader);
	bool expectedLength = (input.length() == (privateHeader.length() + crypto_box_SECRETKEYBYTES*3));
	return hasHeader && expectedLength;
}

bool Utils::checkSodiumPublic(const std::string& input)
{
	std::string publicHeader = SODIUM_PUBLIC_HEADER();
	bool hasHeader = (input.length() > 0 && input.substr(0, publicHeader.length()) == publicHeader);
	bool expectedLength = (input.length() == (publicHeader.length() + crypto_box_PUBLICKEYBYTES*3));
	return hasHeader && expectedLength;
}

std::string Utils::dumpSmallFile(const std::string& path)
{
	std::ifstream fileStream(path);
	std::stringstream stringStream;
	stringStream << fileStream.rdbuf();
	fileStream.close();
	return stringStream.str();
}
