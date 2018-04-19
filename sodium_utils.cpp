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
	unsigned char nonce[crypto_box_NONCEBYTES] = {0};
	randombytes_buf(nonce, crypto_box_NONCEBYTES);

	//setup cipher text
	int cipherTextLength = crypto_box_MACBYTES + inputLength;
	unsigned char cipherText[cipherTextLength] = {0};
	int ret = crypto_box_easy(cipherText, input, inputLength, nonce, yourPublic, myPrivate);
	unsigned char inputLengthDisassembled[JAVA_MAX_PRECISION_INT] = {0};
	disassembleInt(inputLength, JAVA_MAX_PRECISION_INT, inputLengthDisassembled);

	//encryption failed
	if(ret != 0)
	{
		output = NULL;
		outputLength = 0;
		return;
	}

	//assemble the output
	int finalSetupLength = crypto_box_NONCEBYTES+JAVA_MAX_PRECISION_INT+cipherTextLength;
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
	unsigned char nonce[crypto_box_NONCEBYTES];
	memcpy(nonce, input, crypto_box_NONCEBYTES);

	//get the cipher text
	unsigned char messageLengthDisassembled[JAVA_MAX_PRECISION_INT];
	memcpy(messageLengthDisassembled, input+crypto_box_NONCEBYTES, JAVA_MAX_PRECISION_INT);
	int messageLength = reassembleInt(messageLengthDisassembled, JAVA_MAX_PRECISION_INT);
	int cipherLength = inputLength - crypto_box_NONCEBYTES - JAVA_MAX_PRECISION_INT;

	//check to make sure the message length makes sense
	if(messageLength > cipherLength) //this isn't a compression function. not possible
	{
		output = NULL;
		outputLength = 0;
	}

	unsigned char cipherText[cipherLength];
	memcpy(cipherText, input+crypto_box_NONCEBYTES+JAVA_MAX_PRECISION_INT, cipherLength);
	unsigned char* message = new unsigned char[messageLength];

	int ret = crypto_box_open_easy(message, cipherText, cipherLength, nonce, yourPublic, myPrivate);
	if(ret != 0)
	{
		output = std::unique_ptr<unsigned char>(); //pointer to nothing
		outputLength = 0;
		delete message;
		return;
	}
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
