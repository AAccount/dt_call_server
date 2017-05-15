#ifndef DBLOG_H
#define DBLOG_H

//log types
//must match the typeid in the logtype reference table
#define INBOUNDLOG "inbound" //ip in inbound should be the person's ip who sent the command
#define OUTBOUNDLOG "outbound" //ip in outbound should be the person's ip who is getting the response
#define ERRORLOG "error"
#define SYSTEMLOG "system"

#define SELF "dtoperator"
#define SELFIP "self" //not using 127.0.0.1 as this is used for when the error comes from the program itself
					//not any network i/o problem

#define DONTKNOW "???" //when there is no way to guarantee who that it is possible to find out who the user is

//define all the tags here to make it easy to keep track of
#define TAG_INIT "init"
#define TAG_INCOMINGCMD "incoming command socket"
#define TAG_INCOMINGMEDIA "incoming media socket"
#define TAG_DEADSOCK "socket died"
#define TAG_BADCMD "bad command"
#define TAG_LOGIN "login"
#define TAG_CALL "place call"
#define TAG_LOOKUP "lookup"
#define TAG_ACCEPT "accept"
#define TAG_REJECT "reject"
#define TAG_END "call end"
#define TAG_TIMEOUT "call timeout"
#define TAG_MEDIANEW "new media socket"
#define TAG_MEDIACALL "media socket event"
#define TAG_SSLCMD "ssl command write"
#define TAG_CALLTHREAD "call thread"

#include <string>
#include <iostream>
class Log
{
private:
	std::string tag;
	std::string message;
	std::string user;
	std::string type;
	std::string ip;
	uint64_t relatedKey;

public:
	Log(std::string ctag, std::string cmessage, std::string user, std::string type, std::string ip, uint64_t crelatedKey);
	std::string toString();
};

#endif //DBLOG_H
