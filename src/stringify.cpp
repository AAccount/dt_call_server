#include "stringify.hpp"

std::string Stringify::stringify(unsigned char* bytes, int length)
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
		char* stringMemory = &number[0];
		randombytes_buf(stringMemory, number.length());
	}
	return result;
}

void Stringify::destringify(const std::string& input, unsigned char* output)
{
	for(int i=0; i<input.length(); i = i+3)
	{
		std::string digit = input.substr(i, 3);
		output[i/3] = (unsigned char)std::stoi(digit);
		char* stringMemory = &digit[0];
		randombytes_buf(stringMemory, digit.length());
	}
}
