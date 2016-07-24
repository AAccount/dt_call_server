#ifndef DBLOG_H
#define DBLOG_H

//log types
//must be in the sql enum
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
#define TAG_ALARM "alarm killed"
#define TAG_DEADSOCK "socket died"
#define TAG_BADCMD "bad command"
#define TAG_LOGIN "login command"
#define TAG_CALL "call command"
#define TAG_LOOKUP "lookup command"
#define TAG_ACCEPT "accept call command"
#define TAG_REJECT "reject call command"
#define TAG_END "call end command"
#define TAG_TIMEOUT "call timeout command"
#define TAG_MEDIANEW "new media socket"
#define TAG_MEDIACALL "media socket event"

#include <string>

class DBLog
{
private:
	int id;
	long timestamp;
	std::string tag;
	std::string message;
	std::string user;
	std::string type;
	std::string ip;
	unsigned long relatedKey;

public:
	DBLog(int cid, long cts, std::string ctag, std::string cmessage, std::string user, std::string type, std::string ip, unsigned long relatedKey);
	DBLog(long cts, std::string ctag, std::string cmessage, std::string user, std::string type, std::string ip, unsigned long relatedKey);
	DBLog(std::string ctag, std::string cmessage, std::string user, std::string type, std::string ip, unsigned long relatedKey);

	int getId();
	long getTimestamp();
	std::string getTag();
	std::string getMessage();
	std::string getUser();
	std::string getType();
	std::string getIp();
	unsigned long getRelatedKey();
};

#endif //DBLOG_H
