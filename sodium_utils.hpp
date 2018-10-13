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

#include <sodium.h>
#include <string.h>

#include "const.h"

//send a call end command. its own function (unlike the other commands) to detect dropped calls
void sendCallEnd(std::string user);

//sodium asymmetric encrypt
void sodiumEncrypt(bool asym, const unsigned char* input, int inputLength, const unsigned char* myPrivate, const unsigned char* yourPublic, std::unique_ptr<unsigned char>& output, int& outputLength);

//sodium asymmetric decrypt
void sodiumDecrypt(bool asym, const unsigned char* input, int inputLength, const unsigned char* myPrivate, const unsigned char* yourPublic, std::unique_ptr<unsigned char>& output, int& outputLength);

//disassemble/reassemble ints as seen in aclient's utils
int reassembleInt(unsigned char* input, int accuracy);
void disassembleInt(int input, int accuracy, unsigned char* output);

#endif /* SODIUM_UTILS_HPP_ */
