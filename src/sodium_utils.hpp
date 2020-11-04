/*
 * sodium_utils.hpp
 *
 *  Created on: Mar 30, 2018
 *      Author: Daniel
 */

#ifndef SODIUM_UTILS_HPP_
#define SODIUM_UTILS_HPP_
#include <string>
#include <memory>

#include <arpa/inet.h>

#include <sodium.h>
#include <string.h>

namespace SodiumUtils
{
	//sodium asymmetric encrypt
	void sodiumEncrypt(bool asym, const unsigned char* input, int inputLength, const unsigned char* myPrivate, const unsigned char* yourPublic, std::unique_ptr<unsigned char[]>& output, int& outputLength);

	//sodium asymmetric decrypt
	void sodiumDecrypt(bool asym, const unsigned char* input, int inputLength, const unsigned char* myPrivate, const unsigned char* yourPublic, std::unique_ptr<unsigned char[]>& output, int& outputLength);

	//disassemble/reassemble ints as seen in aclient's utils
	int reassembleInt(unsigned char* input);
	void disassembleInt(int input, unsigned char* output);

	//sodium file headers
	inline const std::string SODIUM_PUBLIC_HEADER = "SODIUM PUBLIC KEY\n";
	inline const std::string SODIUM_PRIVATE_HEADER = "SODIUM PRIVATE KEY\n";

	bool checkSodiumPublic(const std::string& input);
	bool checkSodiumPrivate(const std::string& input);

	std::string randomString(int length);
}
#endif /* SODIUM_UTILS_HPP_ */
