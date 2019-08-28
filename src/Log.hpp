#ifndef DBLOG_H
#define DBLOG_H

#include <string>
#include <iostream>
#include <sstream>

class Log
{
public:
	typedef enum {INBOUND, OUTBOUND, ERROR, SYSTEM} TYPE;
	typedef enum {STARTUP, INCOMINGCMD, DEADSOCK, BADCMD, LOGIN, CALL,
		ACCEPT, PASSTHROUGH, READY, END, TCP,
		UDPTHREAD, USERUTILS} TAG;

	TYPE getType() const;
	Log(TAG ctag, const std::string& cmessage, const std::string& user, TYPE type, const std::string& ip);
	std::string toString() const;

	static const std::string& SELF();
	static const std::string& SELFIP();
	static const std::string& DONTKNOW();

private:
	const TAG tag;
	const std::string message;
	const std::string user;
	const TYPE type;
	const std::string ip;
	friend std::ostream& operator<<(std::ostream &strm, const Log&);

	std::string typeString() const;
	std::string tagString() const;
};

#endif //DBLOG_H
