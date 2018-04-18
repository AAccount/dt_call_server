#include "const.h"

//construct on first use workaround for global strings to guarantee they're always there

const std::string& VERSION()
{
	const static std::string value = "6.0:{git revision here}";
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

const std::string& DEFAULTCIPHERS()
{
	const static std::string value = "ECHDE-RSA-AES256-GCM-SHA384:ECHDE-RSA-AES256-SHA256:ECHDE-RSA-AES256-SHA:ECHDE-RSA-AES128-GCM-SHA256:ECHDE-RSA-AES128-SHA256:ECHDE-RSA-AES128-SHA:AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA";
	return value;
}


const std::string& SODIUM_PUBLIC_HEADER()
{
	const static std::string value = "SODIUM PUBLIC KEY\n";
	return value;
}

const std::string& SODIUM_PRIVATE_HEADER()
{
	const static std::string value = "SODIUM PRIVATE KEY\n";
	return value;
}
