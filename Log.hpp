#ifndef DBLOG_H
#define DBLOG_H

#include <string>
#include <iostream>

class Log
{
public:
	typedef enum {INBOUND, OUTBOUND, ERROR, SYSTEM} TYPE;
	typedef enum {STARTUP, INCOMINGCMD, DEADSOCK, BADCMD, LOGIN, CALL,
		ACCEPT, PASSTHROUGH, READY, END, SSL,
		UDPTHREAD, USERUTILS} TAG;

	TYPE getType() const;
	Log(TAG ctag, std::string cmessage, std::string user, TYPE type, std::string ip);

	static const std::string& SELF();
	static const std::string& SELFIP();
	static const std::string& DONTKNOW();

private:
	TAG tag;
	std::string message;
	std::string user;
	TYPE type;
	std::string ip;
	friend std::ostream& operator<<(std::ostream &strm, const Log&);

	std::string typeString() const;
	std::string tagString() const;
};

#endif //DBLOG_H
