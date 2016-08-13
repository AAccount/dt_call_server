#include "dblog.hpp"

using namespace std;

DBLog::DBLog(int cid, uint64_t cts, int ctag, string cmessage, string cuser, int ctype, string cip, uint64_t crelatedKey)
{
	id = cid;
	timestamp = cts;
	tag = ctag;
	message=cmessage;
	user = cuser;
	type = ctype;
	ip = cip;
	relatedKey = crelatedKey;
}

DBLog::DBLog(uint64_t cts, int ctag, string cmessage, string cuser, int ctype, string cip, uint64_t crelatedKey)
{
	id = 0; //new log, won't have an id yet. initialize to clear out old data
	timestamp = cts;
	tag = ctag;
	message=cmessage;
	user = cuser;
	type = ctype;
	ip = cip;
	relatedKey = crelatedKey;
}

int DBLog::getId()
{
	return id;
}

uint64_t DBLog::getTimestamp()
{
	return timestamp;
}

int DBLog::getTag()
{
	return tag;
}

string DBLog::getMessage()
{
#ifndef VERBOSE
//strip newlines from the message for more pleasant terminal output
	size_t length = message.length();
	if(message.at(length-1) == '\n')
	{
		message = message.substr(0, length-1);
	}
#endif
	return message;
}

string DBLog::getUser()
{
	return user;
}

int DBLog::getType()
{
	return type;
}

string DBLog::getIp()
{
	return ip;
}

uint64_t DBLog::getRelatedKey()
{
	return relatedKey;
}
