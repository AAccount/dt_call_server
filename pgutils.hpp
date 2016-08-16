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
		uint64_t authenticate(string username, string password, uint64_t relatedKey);
		void setFd(uint64_t sessionid, int fd, int which, uint64_t relatedKey);
		void clearSession(string username, uint64_t relatedKey);

		//db verification functions
		bool verifySessionid(uint64_t sessionid, int fd, uint64_t relatedKey);
		bool doesUserExist(string name, uint64_t relatedKey);

		//db lookup functions
		string userFromFd(int fd, int which, uint64_t relatedKey);
		string userFromSessionid(uint64_t sessionid, uint64_t relatedKey);
		int userFd(string user, int which, uint64_t relatedKey);
		uint64_t userSessionId(string uname, uint64_t relatedKey);
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
