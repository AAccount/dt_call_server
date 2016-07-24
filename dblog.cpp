#include "dblog.hpp"

using namespace std;

DBLog::DBLog(int cid, long cts, string ctag, string cmessage, string cuser, string ctype, string cip, unsigned long crelatedKey)
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

DBLog::DBLog(long cts, string ctag, string cmessage, string cuser, string ctype, string cip, unsigned long crelatedKey)
{
	timestamp = cts;
	tag = ctag;
	message=cmessage;
	user = cuser;
	type = ctype;
	ip = cip;
	relatedKey = crelatedKey;
}

DBLog::DBLog(string ctag, string cmessage, string cuser, string ctype, string cip, unsigned long crelatedKey)
{
	id = 0; //log that isn't in the db yet
	timestamp = time(NULL);
	tag = ctag;
	message = cmessage;
	user = cuser;
	type = ctype;
	ip = cip;
	relatedKey = crelatedKey;
}

int DBLog::getId()
{
	return id;
}

long DBLog::getTimestamp()
{
	return timestamp;
}

string DBLog::getTag()
{
	return tag;
}

string DBLog::getMessage()
{
	return message;
}

string DBLog::getUser()
{
	return user;
}

string DBLog::getType()
{
	return type;
}

string DBLog::getIp()
{
	return ip;
}

unsigned long DBLog::getRelatedKey()
{
	return relatedKey;
}
