#include <pqxx/pqxx>
#include "const.h"

using namespace std;
using namespace pqxx;

class PGUtils
{//it is NOT the job of PGUtils to validate input from the command string.
	public:
		static PGUtils* getInstance();
		//db set/write functions
		long authenticate(string username, string password);
		void setFd(long sessionid, int fd, int which);
		void clearSession(string username);
		//db verification functions
		bool verifySessionid(long sessionid, int fd);
		bool doesUserExist(string name);
		//db lookup functions
		string userFromFd(int fd, int which);
		string userFromSessionid(long sessionid);
		int userFd(string user, int which);
		long userSessionId(string uname);
#ifdef MEMCHECK
		void killInstance();
#endif
	private:
		PGUtils();
		connection dbconn; //db connection
		static PGUtils *instance;
#ifdef MEMCHECK
		static int counter;
#endif
};
