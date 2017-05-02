#include "Log.hpp"

#include <iostream>
using namespace std;

Log::Log(string ctag, string cmessage, string cuser, string ctype, string cip, uint64_t crelatedKey)
{
	tag = ctag;
	message=cmessage;
	user = cuser;
	type = ctype;
	ip = cip;
	relatedKey = crelatedKey;
}

string Log::toString()
{
	time_t now = time(0);
	string nowStamp = string(ctime(&now));
	nowStamp = nowStamp.substr(0, nowStamp.length()-1);
	return  nowStamp + " tag=" + tag
			+ "; message=" + message + "; user=" + user + "; type=" + type + "; ip="
			+ ip + "; relatedkey=" + to_string(relatedKey);
}
