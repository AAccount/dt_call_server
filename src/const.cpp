#include "const.h"

//construct on first use workaround for global strings to guarantee they're always there

const std::string& VERSION()
{
	const static std::string value = "7.6: {git revision here}";
	return value;
}

const std::string& SESSION_KEY_PLACEHOLDER()
{
	const static std::string value = "SESSION_KEY_HERE";
	return value;
}

const std::string& AES_PLACEHOLDER()
{
	const static std::string value = "ENCRYPTED_AES_KEY_HERE";
	return value;
}

const std::string& JBYTE()
{
	const static std::string value = "D";
	return value;
}
