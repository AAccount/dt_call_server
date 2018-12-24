#include "const.h"

//construct on first use workaround for global strings to guarantee they're always there

const std::string& VERSION()
{
	const static std::string value = "7.3: {git revision here}";
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

const std::string& CONFFILE()
{
#ifdef LIVE
	const static std::string value = "/etc/dtoperator/dtoperator.conf";
#else
	const static std::string value = "/home/Daniel/dtoperator/dtoperator.conf";
#endif
	return value;
}

const std::string& USERSFILE()
{
#ifdef LIVE
	const static std::string value = "/etc/dtoperator/users";
#else
	const static std::string value = "/home/Daniel/dtoperator/users";
#endif
	return value;
}

const std::string& LOGFOLDER()
{
#ifdef LIVE
	const static std::string value = "/var/log/dtoperator/";
#else
	const static std::string value = "/tmp/";
#endif
	return value;
}

const std::string& LOGPREFIX()
{
	const static std::string value = "log ";
	return value;
}
