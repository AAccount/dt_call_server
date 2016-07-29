#ifndef PGUTILS_H
#define PGUTILS_H

#include <unordered_map> //hash table
#include <pqxx/pqxx>
#include "const.h"
#include "dblog.hpp"

using namespace std;
using namespace pqxx;

class PGUtils
{//it is NOT the job of PGUtils to validate input from the command string.
	public:
		static PGUtils* getInstance();
		//db set/write functions
		unsigned long authenticate(string username, string password);
		void setFd(unsigned long sessionid, int fd, int which);
		void clearSession(string username);
		//db verification functions
		bool verifySessionid(unsigned long sessionid, int fd);
		bool doesUserExist(string name);
		//db lookup functions
		string userFromFd(int fd, int which);
		string userFromSessionid(unsigned long sessionid);
		int userFd(string user, int which);
		unsigned long userSessionId(string uname);
		void killInstance();
		//log related functions
		void insertLog(DBLog l);
	private:
		PGUtils();
		connection dbconn; //db connection
		static PGUtils *instance;
		unordered_map<int, string> tagNames;
};

#endif //PGUTILS_H
