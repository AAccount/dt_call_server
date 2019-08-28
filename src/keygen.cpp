#include "keygen.hpp"

int main(int argc, char** argv)
{
	//initialize library
	if(sodium_init() < 0)
	{
		std::cout << "Couldn't initialize sodium library\n";
		return 1;
	}

	//get the person's name
	std::cout << "Generating keys for: ";
	std::string name;
	std::cin >> name;

	//generate keys
	unsigned char publicKey[crypto_box_PUBLICKEYBYTES] = {};
	unsigned char privateKey[crypto_box_SECRETKEYBYTES] = {};
	crypto_box_keypair(publicKey, privateKey);

	//stringify
	const std::string publicKeyString = SodiumUtils::SODIUM_PUBLIC_HEADER() + Stringify::stringify(publicKey, crypto_box_PUBLICKEYBYTES);
	const std::string privateKeyString = SodiumUtils::SODIUM_PRIVATE_HEADER() + Stringify::stringify(privateKey, crypto_box_SECRETKEYBYTES);

	//export to /tmp
	const std::string publicLocation = "/tmp/"+name+"_public.na";
	std::cout << "Writing sodium public key file to: " << publicLocation << "\n";
	std::ofstream publicFile(publicLocation);
	publicFile << publicKeyString;
	publicFile.close();

	const std::string privateLocation = "/tmp/"+name+"_private.na";
	std::cout << "Writing sodium private key file to: " << privateLocation << "\n";
	std::ofstream privateFile(privateLocation);
	privateFile << privateKeyString;
	privateFile.close();

	randombytes_buf(privateKey, crypto_box_SECRETKEYBYTES);
	const char* privateKeyStringMemory = &privateKeyString[0];
	randombytes_buf((void*)privateKeyStringMemory, privateKeyString.length());

	return 0;
}
