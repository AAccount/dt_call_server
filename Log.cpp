#include "Log.hpp"

#include <iostream>

const std::string& Log::SELF()
{
	const static std::string value = "dtoperator";
	return value;
}

const std::string& Log::SELFIP()
{
	const static std::string value = "127.0.0.1";
	return value;
}

const std::string& Log::DONTKNOW()
{
	const static std::string value = "???";
	return value;
}

Log::Log(TAG ctag, std::string cmessage, std::string cuser, TYPE ctype, std::string cip)
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
	return strm << nowStamp << " tag=" << l.tagString()
			<< "; message=" << l.message << "; user=" << l.user << "; type=" << l.typeString() << "; ip="
			<< l.ip + ";";
}

Log::TYPE Log::getType() const
{
	return type;
}

std::string Log::typeString() const
{
	switch(type)
	{
	case INBOUND:
		return "inbound";
	case OUTBOUND:
		return "outbound";
	case ERROR:
		return "error";
	case SYSTEM:
		return "system";
	default:
		return "";
	}
}

std::string Log::tagString() const
{
	switch(tag)
	{
	case STARTUP:
		return "startup";
	case INCOMINGCMD:
		return "incoming command socket";
	case DEADSOCK:
		return "socket died";
	case BADCMD:
		return "bad command";
	case LOGIN:
		return "login";
	case CALL:
		return "place call";
	case ACCEPT:
		return "accept";
	case PASSTHROUGH:
		return "passthrough";
	case READY:
		return "ready";
	case END:
		return "call end";
	case SSL:
		return "ssl socket write";
	case UDPTHREAD:
		return "udp thread";
	case USERUTILS:
		return "user utils";
	default:
		return "";
	}
}
