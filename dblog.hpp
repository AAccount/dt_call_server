#ifndef DBLOG_H
#define DBLOG_H

//log types
//must match the typeid in the logtype reference table
#define INBOUNDLOG 1 //ip in inbound should be the person's ip who sent the command
#define OUTBOUNDLOG 2 //ip in outbound should be the person's ip who is getting the response
#define ERRORLOG 3
#define SYSTEMLOG 4

#define SELF "dtoperator"
#define SELFIP "self" //not using 127.0.0.1 as this is used for when the error comes from the program itself
					//not any network i/o problem

#define DONTKNOW "???" //when there is no way to guarantee who that it is possible to find out who the user is

//define all the tags here to make it easy to keep track of
//must match the tagid in the tag reference table
#define TAG_INIT 1
#define TAG_INCOMINGCMD 2
#define TAG_INCOMINGMEDIA 3
#define TAG_ALARM 4
#define TAG_DEADSOCK 5
#define TAG_BADCMD 6
#define TAG_LOGIN 7
#define TAG_CALL 8
#define TAG_LOOKUP 9
#define TAG_ACCEPT 10
#define TAG_REJECT 11
#define TAG_END 12
#define TAG_TIMEOUT 13
#define TAG_MEDIANEW 14
#define TAG_MEDIACALL 15
#define TAG_SSLCMD 26

//postgres utilities tags
#define TAG_POSTGRES_AUTH 16
#define TAG_POSTGRES_SETFD 17
#define TAG_POSTGRES_CLEARSESS 18
#define TAG_POSTGRES_VERIFYSESS 19
#define TAG_POSTGRES_USEREXISTS 20
#define TAG_POSTGRES_UFROMFD 21
#define TAG_POSTGRES_UFROMSESS 22
#define TAG_POSTGRES_FDFROMU 23
#define TAG_POSTGRES_SESSFROMU 24
#define TAG_POSTGRES_UTHERE 25

#include <string>
#include <iostream>
class DBLog
{
private:
	int id;
	uint64_t timestamp;
	int tag;
	std::string message;
	std::string user;
	int type;
	std::string ip;
	uint64_t relatedKey;
	friend std::ostream& operator<<(std::ostream&, const DBLog&);
public:
	DBLog(int cid, uint64_t cts, int ctag, std::string cmessage, std::string user, int type, std::string ip, uint64_t crelatedKey);
	DBLog(uint64_t cts, int ctag, std::string cmessage, std::string user, int type, std::string ip, uint64_t crelatedKey);
	DBLog(uint64_t cts, int ctag, std::string cmessage, int type, uint64_t crelatedKey);

	int getId();
	uint64_t getTimestamp();
	int getTag();
	std::string getMessage();
	std::string getUser();
	int getType();
	std::string getIp();
	uint64_t getRelatedKey();
};

#endif //DBLOG_H
