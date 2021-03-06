/*
 * sodium_utils.cpp
 *
 *  Created on: Mar 30, 2018
 *      Author: Daniel
 */

#include "sodium_utils.hpp"

bool SodiumUtils::checkSodiumPrivate(const std::string& input)
{
	std::string privateHeader = SODIUM_PRIVATE_HEADER;
	bool hasHeader = (input.length() > 0 && input.substr(0, privateHeader.length()) == privateHeader);
	bool expectedLength = (input.length() == (privateHeader.length() + crypto_box_SECRETKEYBYTES*3));
	return hasHeader && expectedLength;
}

bool SodiumUtils::checkSodiumPublic(const std::string& input)
{
	std::string publicHeader = SODIUM_PUBLIC_HEADER;
	bool hasHeader = (input.length() > 0 && input.substr(0, publicHeader.length()) == publicHeader);
	bool expectedLength = (input.length() == (publicHeader.length() + crypto_box_PUBLICKEYBYTES*3));
	return hasHeader && expectedLength;
}

std::string SodiumUtils::randomString(int length)
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

void SodiumUtils::sodiumEncrypt(bool asym, const unsigned char* input, int inputLength, const unsigned char* myPrivate, const unsigned char* yourPublic, std::unique_ptr<unsigned char[]>& output, int& outputLength)
{
	//setup nonce (like password salt)
	int nonceLength = crypto_secretbox_NONCEBYTES;
	if(asym)
	{
		nonceLength = crypto_box_NONCEBYTES;
	}
	std::unique_ptr<unsigned char[]> nonceArray = std::make_unique<unsigned char[]>(nonceLength);
	unsigned char* nonce = nonceArray.get();
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
		outputLength = 0;
		return;
	}

	unsigned char messageLengthDisassembled[sizeof(uint32_t)] = {};
	disassembleInt(inputLength, messageLengthDisassembled);

	//assemble the output
	const int finalSetupLength = crypto_box_NONCEBYTES+sizeof(uint32_t)+cipherTextLength;
	memset(output.get(), 0, finalSetupLength);
	memcpy(output.get(), nonce, crypto_box_NONCEBYTES);
	memcpy(output.get()+crypto_box_NONCEBYTES, messageLengthDisassembled, sizeof(uint32_t));
	memcpy(output.get()+crypto_box_NONCEBYTES+sizeof(uint32_t), cipherText, cipherTextLength);

	outputLength = finalSetupLength;
	//output[nonce|message length|encrypted]
}

void SodiumUtils::sodiumDecrypt(bool asym, const unsigned char* input, int inputLength, const unsigned char* myPrivate, const unsigned char* yourPublic, std::unique_ptr<unsigned char[]>& output, int& outputLength)
{
	//input[nonce|message length|encrypted]

	//extracts nonce (sorta like a salt)
	int nonceLength = crypto_secretbox_NONCEBYTES;
	if(asym)
	{
		nonceLength = crypto_box_NONCEBYTES;
	}

	if(nonceLength > inputLength)
	{
		//invalid encrypted bytes, doesn't have a nonce
		outputLength = 0;
		return;
	}
	std::unique_ptr<unsigned char[]> nonceArray = std::make_unique<unsigned char[]>(nonceLength);
	unsigned char* nonce = nonceArray.get();
	memcpy(nonce, input, nonceLength);

	//get the message length (and figure out the cipher text length)
	if((nonceLength + sizeof(uint32_t)) > inputLength)
	{
		//invalid encrypted bytes, doesn't have a message length
		outputLength = 0;
		return;
	}
	unsigned char messageLengthDisassembled[sizeof(uint32_t)];
	memcpy(messageLengthDisassembled, input+crypto_box_NONCEBYTES, sizeof(uint32_t));
	const int messageLength = reassembleInt(messageLengthDisassembled);
	const int cipherLength = inputLength - crypto_box_NONCEBYTES - sizeof(uint32_t);

	//check to make sure the message length makes sense
	const bool messageCompressed = messageLength > cipherLength; //this isn't a compression function. not possible
	const bool messageMIA = messageLength < 1;
	if(messageCompressed || messageMIA)
	{
		outputLength = 0;
		return;
	}

	std::unique_ptr<unsigned char[]> cipherTextArray = std::make_unique<unsigned char[]>(cipherLength);
	unsigned char* cipherText = cipherTextArray.get();
	memcpy(cipherText, input+crypto_box_NONCEBYTES+sizeof(uint32_t), cipherLength);
	//store the message in somewhere it is guaranteed to fit in case messageLength is bogus/malicious
	std::unique_ptr<unsigned char[]> messageStorageArray = std::make_unique<unsigned char[]>(cipherLength);
	unsigned char* messageStorage = messageStorageArray.get();

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
		outputLength = 0;
		return;
	}

	//now that the message has been successfully decrypted, take in on blind faith messageLength makes was ok
	//	up to the next function to make sure the decryption contents aren't truncated by a malicious messageLength
	memcpy(output.get(), messageStorage, messageLength);
	outputLength = messageLength;
}

void SodiumUtils::disassembleInt(int input, unsigned char* output)
{
	input = htonl(input);
	memcpy(output, &input, sizeof(uint32_t));
}

int SodiumUtils::reassembleInt(unsigned char* input)
{
	int result = 0;
	memcpy(&result, input, sizeof(uint32_t));
	return ntohl(result);
}
