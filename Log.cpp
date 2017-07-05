#include "Log.hpp"

#include <iostream>

Log::Log(std::string ctag, std::string cmessage, std::string cuser, std::string ctype, std::string cip)
{
	tag = ctag;
	message=cmessage;
	user = cuser;
	type = ctype;
	ip = cip;
}

std::ostream& operator<<(std::ostream &strm, const Log &l)
{
	time_t now = time(0);
	std::string nowStamp = std::string(ctime(&now));
	nowStamp = nowStamp.substr(0, nowStamp.length()-1);
	return strm << nowStamp << " tag=" << l.tag
			<< "; message=" << l.message << "; user=" << l.user << "; type=" << l.type << "; ip="
			<< l.ip + ";";
}

std::string Log::getType()
{
	return type;
}
