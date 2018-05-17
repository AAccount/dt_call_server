/*
 * sodium_utils.cpp
 *
 *  Created on: Mar 30, 2018
 *      Author: Daniel
 */

#include "sodium_utils.hpp"

void sodiumAsymEncrypt(unsigned char* input, int inputLength, unsigned char* myPrivate, unsigned char* yourPublic, std::unique_ptr<unsigned char>& output, int& outputLength)
{
	//setup nonce (like password salt)
	unsigned char nonce[crypto_box_NONCEBYTES] = {};
	randombytes_buf(nonce, crypto_box_NONCEBYTES);

	//setup cipher text
	const int cipherTextLength = crypto_box_MACBYTES + inputLength;
	unsigned char cipherText[cipherTextLength] = {};
	const int ret = crypto_box_easy(cipherText, input, inputLength, nonce, yourPublic, myPrivate);
	unsigned char inputLengthDisassembled[JAVA_MAX_PRECISION_INT] = {};
	disassembleInt(inputLength, JAVA_MAX_PRECISION_INT, inputLengthDisassembled);

	//encryption failed
	if(ret != 0)
	{
		output = std::unique_ptr<unsigned char>(); //pointer to nothing
		outputLength = 0;
		return;
	}

	//assemble the output
	const int finalSetupLength = crypto_box_NONCEBYTES+JAVA_MAX_PRECISION_INT+cipherTextLength;
	unsigned char* finalSetup = new unsigned char[finalSetupLength];
	memset(finalSetup, 0, finalSetupLength);
	memcpy(finalSetup, nonce, crypto_box_NONCEBYTES);
	memcpy(finalSetup+crypto_box_NONCEBYTES, inputLengthDisassembled, JAVA_MAX_PRECISION_INT);
	memcpy(finalSetup+crypto_box_NONCEBYTES+JAVA_MAX_PRECISION_INT, cipherText, cipherTextLength);
	output = std::unique_ptr<unsigned char>(finalSetup);
	outputLength = finalSetupLength;

	//output[nonce|message length|encrypted]
}

void sodiumAsymDecrypt(unsigned char* input, int inputLength, unsigned char* myPrivate, unsigned char* yourPublic, std::unique_ptr<unsigned char>& output, int& outputLength)
{
	//input[nonce|message length|encrypted]

	//extracts nonce (sorta like a salt)
	if(crypto_box_NONCEBYTES > inputLength)
	{
		//invalid encrypted bytes, doesn't have a nonce
		output = std::unique_ptr<unsigned char>(); //pointer to nothing
		outputLength = 0;
		return;
	}
	unsigned char nonce[crypto_box_NONCEBYTES];
	memcpy(nonce, input, crypto_box_NONCEBYTES);

	//get the message length (and figure out the cipher text length)
	if((crypto_box_NONCEBYTES + JAVA_MAX_PRECISION_INT) > inputLength)
	{
		//invalid encrypted bytes, doesn't have a message length
		output = std::unique_ptr<unsigned char>(); //pointer to nothing
		outputLength = 0;
		return;
	}
	unsigned char messageLengthDisassembled[JAVA_MAX_PRECISION_INT];
	memcpy(messageLengthDisassembled, input+crypto_box_NONCEBYTES, JAVA_MAX_PRECISION_INT);
	const int messageLength = reassembleInt(messageLengthDisassembled, JAVA_MAX_PRECISION_INT);
	const int cipherLength = inputLength - crypto_box_NONCEBYTES - JAVA_MAX_PRECISION_INT;

	//check to make sure the message length makes sense
	const bool messageCompressed = messageLength > cipherLength; //this isn't a compression function. not possible
	const bool messageMIA = messageLength < 1;
	if(messageCompressed || messageMIA)
	{
		output = std::unique_ptr<unsigned char>(); //pointer to nothing
		outputLength = 0;
		return;
	}

	unsigned char cipherText[cipherLength] = {};
	memcpy(cipherText, input+crypto_box_NONCEBYTES+JAVA_MAX_PRECISION_INT, cipherLength);
	//store the message in somewhere it is guaranteed to fit in case messageLength is bogus/malicious
	unsigned char messageStorage[cipherLength] = {};

	int ret = crypto_box_open_easy(messageStorage, cipherText, cipherLength, nonce, yourPublic, myPrivate);
	if(ret != 0)
	{
		output = std::unique_ptr<unsigned char>(); //pointer to nothing
		outputLength = 0;
		return;
	}

	//now that the message has been successfully decrypted, take in on blind faith messageLength makes was ok
	//	up to the next function to make sure the decryption contents aren't truncated by a malicious messageLength
	unsigned char* message = new unsigned char[messageLength];
	memcpy(message, messageStorage, messageLength);
	output = std::unique_ptr<unsigned char>(message);
	outputLength = messageLength;
}

void disassembleInt(int input, int accuracy, unsigned char* output)
{
	for(int i=0; i<accuracy; i++)
	{
		output[i] = (unsigned char)((input >> (SIZEOF_JBYTE*(accuracy-1-i))) & 127); //127 = 0111 1111 because of java's forced signed byte
	}
}

int reassembleInt(unsigned char* input, int accuracy)
{
	int result = 0;
	for(int i=0; i<accuracy; i++)
	{
		result = result +((int)input[i]) << (SIZEOF_JBYTE*(accuracy-1-i));
	}
	return result;
}
