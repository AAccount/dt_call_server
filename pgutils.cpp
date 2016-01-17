#include <time.h>

#include <pqxx/pqxx>
#include <random>
#include <iostream>

#include "const.h"
#include "pgutils.hpp"

using namespace std;
using namespace pqxx;

//declare all static variables
PGUtils* PGUtils::instance;
#ifdef MEMCHECK
int PGUtils::counter = 1;
#endif

//constructor
PGUtils::PGUtils()
: dbconn("dbname=call")
{
	
}

//public functions
PGUtils* PGUtils::getInstance() //don't need to declare static again
{
	if(instance == NULL)
	{
		instance = new PGUtils();
	}
	return instance;
}

long PGUtils::authenticate(string username, string password)
{//TODO: remove error specifics like no user etc and turn it into "authentication failure" or similar

	//sql statements
	const string hash = "select saltedhash from users where username=$1";
	const string auth = "select count(*) from users where username=$1 and saltedhash=crypt($2, $3)";
	const string timestamp = "update users set sessionid=$1 where username=$2";

	//get the salted hash for verification
	dbconn.prepare("hash", hash);
	work getHash(dbconn);
	result resultHash = getHash.prepared("hash")(username).exec();
	getHash.commit();
	if(resultHash.size() < 1)
	{//no use continuing if the user doesn't exist
		return ENOUSER;	
	}
	string saltedHash = resultHash[0][0].as<string>();

	//now authentiate the user against the db
	dbconn.prepare("auth", auth);
	work getAuth(dbconn);
	result resultAuth = getAuth.prepared("auth")(username)(password)(saltedHash).exec();
	getAuth.commit();
	if(resultAuth[0][0].as<int>() != 1)
	{
		return EPASS;
	}

	// https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
	// https://stackoverflow.com/questions/19665818/best-way-to-generate-random-numbers-using-c11-random-library
	//generate random # session key
/*
	const char alphanum[] =//leaving out semicolon for command string tokenizing
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<int> dist (0, sizeof(alphanum)-1);
	string sessionid = "";
	for(int i=0; i<50; i++)
	{//if sessionid is too long, it gets cut off when going into the db through the prepared statement
		sessionid = sessionid + alphanum[dist(mt)];
	}
*/
	//pqxx truncates random strings... randomly. very annoying. not sure how to work around.
	//use large random number instead
#ifdef MEMCHECK
	long sessionid = counter; //get around valgrind sigill for rdrand on 5960X haswell
	counter++;
#else
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<unsigned long> dist (0, 9223372036854775807);
	long sessionid = dist(mt);
#endif
	try
	{
		dbconn.prepare("timestamp", timestamp);
		work setTimestamp(dbconn);
		setTimestamp.prepared("timestamp")(sessionid)(username).exec();
		setTimestamp.commit();
	}
	catch(exception &e)
	{//couldn't write to the db. attempt the login again
		//TODO: log error somewhere
		cout << "exception " << e.what() << "\n";
		return EGENERIC;
	}
	return sessionid;
}

void PGUtils::setFd(long sessionid, int fd, int which)
{
	const string setCmd = "update users set commandfd=$1 where sessionid=$2";
	const string setMedia = "update users set mediafd=$1 where sessionid=$2";

	if(which == COMMAND)
	{
		dbconn.prepare("setCmd", setCmd);
		work setFd(dbconn);
		setFd.prepared("setCmd")(fd)(sessionid).exec();
		setFd.commit();
	}
	else if (which == MEDIA)
	{
		dbconn.prepare("setMedia", setMedia);
		work setFd(dbconn);
		setFd.prepared("setMedia")(fd)(sessionid).exec();
		setFd.commit();
	}
	else
	{
		cout << "erroneous fd type specified: " << which << "\n";
		return; //you didn't choose an appropriate server fd
	}
}

void PGUtils::clearSession(string username)
{
	const string clear = "update users set commandfd=NULL, mediafd=NULL, sessionid=NULL where username=$1";
	dbconn.prepare("clear", clear);
	work clearInfo(dbconn);
	clearInfo.prepared("clear")(username).exec();
	clearInfo.commit();
}

//make ABSOLUTELY SURE this can't be called before verifying the user's sessionid to avoid scripted
//	lookups of who is in the database
bool PGUtils::verifySessionid(long sessionid, int fd)
{
	const string verify = "select count(*) from users where commandfd=$1 and sessionid=$2";

	dbconn.prepare("verify", verify);
	work verifySessionid(dbconn);
	result dbresult = verifySessionid.prepared("verify")(fd)(sessionid).exec();
	verifySessionid.commit();
	if(dbresult[0][0].as<int>() == 1)
	{
		return true;
	}
	return false;
}

string PGUtils::userFromFd(int fd, int which)
{//makes the assumption you verified the session id sent from this fd is valid

	if(which == COMMAND)
	{
		const string userFromCmd = "select username from users where commandfd=$1";
	
		dbconn.prepare("userFromCmd", userFromCmd);
		work cmd2User(dbconn);
		result dbresult = cmd2User.prepared("userFromCmd")(fd).exec();
		if(dbresult.size() > 0)
		{
			return dbresult[0][0].as<string>();
		}
		return "ENOUSER"; //just in case something happened in between
	}
	else if(which == MEDIA)
	{
		const string userFromMedia = "select username from users where mediafd=$1";
	
		dbconn.prepare("userFromMedia", userFromMedia);
		work media2User(dbconn);
		result dbresult = media2User.prepared("userFromMedia")(fd).exec();
		if(dbresult.size() > 0)
		{
			return dbresult[0][0].as<string>();
		}
		return "ENOUSER"; //just in case something happened in between
	}
	cout << "erroneous fd type specified: " << which << "\n";
	return "EPARAM";
}

string PGUtils::userFromSessionid(long sessionid)
{
	const string userFromSession = "select username from users where sessionid=$1";
	
	dbconn.prepare("userFromSession", userFromSession);
	work id2User(dbconn);
	result dbresult = id2User.prepared("userFromSession")(sessionid).exec();
	if(dbresult.size() > 0)
	{
		return dbresult[0][0].as<string>();	
	}
	return "ENOUSER";
}

int PGUtils::userFd(string user, int which)
{
	if(which == COMMAND)
	{
		const string findCmd = "select commandfd from users where username=$1";

		dbconn.prepare("findCmd", findCmd);
		work user2Fd(dbconn);
		result dbresult = user2Fd.prepared("findCmd")(user).exec();
		user2Fd.commit();
		if(dbresult.size() > 0)
		{
			try
			{
				return dbresult[0][0].as<int>();
			}
			catch(conversion_error &e)
			{
				return EGENERIC;
			}
		}
		return ENOFD;
	}
	else if (which == MEDIA)
	{
		const string findMediaFd = "select mediafd from users where username=$1";

		dbconn.prepare("findMediaFd", findMediaFd);
		work user2Fd(dbconn);
		result dbresult = user2Fd.prepared("findMediaFd")(user).exec();
		user2Fd.commit();
		if(dbresult.size() > 0)
		{
			try
			{
				return dbresult[0][0].as<int>();
			}
			catch(conversion_error &e)
			{
				return EGENERIC;
			}
		}
		return ENOFD;
	}
	return EPARAM;
}

bool PGUtils::doesUserExist(string name)
{
	const string queryUser = "select username from users where username=$1";

	dbconn.prepare("queryUser", queryUser);
	work wQueryUser(dbconn);
	result dbresult = wQueryUser.prepared("queryUser")(name).exec();
	wQueryUser.commit();
	if(dbresult.size() > 0)
	{
		return true;
	}
	return false;
}

long PGUtils::userSessionId(string uname)
{
	const string querySess = "select sessionid from users where username=$1";
	dbconn.prepare("querySess", querySess);
	work wQuerySess(dbconn);
	result dbresult = wQuerySess.prepared("querySess")(uname).exec();
	if(dbresult.size() > 0)
	{
		return dbresult[0][0].as<long>();
	}
	return EPARAM;
}

#ifdef MEMCHECK
void PGUtils::killInstance()
{
	delete instance;
}
#endif







