/*
 * sodium_utils.cpp
 *
 *  Created on: Mar 30, 2018
 *      Author: Daniel
 */

#include "sodium_utils.hpp"

void sodiumEncrypt(bool asym, const unsigned char* input, int inputLength, const unsigned char* myPrivate, const unsigned char* yourPublic, std::unique_ptr<unsigned char>& output, int& outputLength)
{
	//setup nonce (like password salt)
	int nonceLength = 0;
	if(asym)
	{
		nonceLength = crypto_box_NONCEBYTES;
	}
	else
	{
		nonceLength = crypto_secretbox_NONCEBYTES;
	}
	unsigned char nonce[nonceLength] = {};
	randombytes_buf(nonce, nonceLength);

	//setup cipher text
	int cipherTextLength = 0, libsodiumOK = 0;
	unsigned char cipherText[2000] = {}; //guaranteed bigger than MTU of 1500
	if(asym)
	{
		cipherTextLength = crypto_box_MACBYTES + inputLength;
		libsodiumOK = crypto_box_easy(cipherText, input, inputLength, nonce, yourPublic, myPrivate);
	}
	else
	{
		cipherTextLength = crypto_secretbox_MACBYTES + inputLength;
		libsodiumOK = crypto_secretbox_easy(cipherText, input, inputLength, nonce, myPrivate); //myPrivate more like "ourPrivate" for symmetric
	}

	//encryption failed
	if(libsodiumOK != 0)
	{
		output = std::unique_ptr<unsigned char>(); //pointer to nothing
		outputLength = 0;
		return;
	}
	unsigned char messageLengthDisassembled[JAVA_MAX_PRECISION_INT] = {};
	disassembleInt(inputLength, JAVA_MAX_PRECISION_INT, messageLengthDisassembled);

	//assemble the output
	const int finalSetupLength = crypto_box_NONCEBYTES+JAVA_MAX_PRECISION_INT+cipherTextLength;
	unsigned char* finalSetup = new unsigned char[finalSetupLength];
	memset(finalSetup, 0, finalSetupLength);
	memcpy(finalSetup, nonce, crypto_box_NONCEBYTES);
	memcpy(finalSetup+crypto_box_NONCEBYTES, messageLengthDisassembled, JAVA_MAX_PRECISION_INT);
	memcpy(finalSetup+crypto_box_NONCEBYTES+JAVA_MAX_PRECISION_INT, cipherText, cipherTextLength);
	output = std::unique_ptr<unsigned char>(finalSetup);
	outputLength = finalSetupLength;

	//output[nonce|message length|encrypted]
}

void sodiumDecrypt(bool asym, const unsigned char* input, int inputLength, const unsigned char* myPrivate, const unsigned char* yourPublic, std::unique_ptr<unsigned char>& output, int& outputLength)
{
	//input[nonce|message length|encrypted]

	//extracts nonce (sorta like a salt)
	int nonceLength = 0;
	if(asym)
	{
		nonceLength = crypto_box_NONCEBYTES;
	}
	else
	{
		nonceLength = crypto_secretbox_NONCEBYTES;
	}
	if(nonceLength > inputLength)
	{
		//invalid encrypted bytes, doesn't have a nonce
		output = std::unique_ptr<unsigned char>(); //pointer to nothing
		outputLength = 0;
		return;
	}
	unsigned char nonce[nonceLength] = {};
	memcpy(nonce, input, nonceLength);

	//get the message length (and figure out the cipher text length)
	if((nonceLength + JAVA_MAX_PRECISION_INT) > inputLength)
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

	int libsodiumOK = 0;
	if(asym)
	{
		libsodiumOK = crypto_box_open_easy(messageStorage, cipherText, cipherLength, nonce, yourPublic, myPrivate);
	}
	else
	{
		libsodiumOK = crypto_secretbox_open_easy(messageStorage, cipherText, cipherLength, nonce, myPrivate);
	}

	if(libsodiumOK != 0)
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
