#include <time.h>

#include <pqxx/pqxx>
#include <random>
#include <iostream>
#include <unordered_map> //hash table

#include "const.h"
#include "pgutils.hpp"

#include "dblog.hpp"

using namespace std;
using namespace pqxx;

//declare all static variables
PGUtils* PGUtils::instance;

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

unsigned long PGUtils::authenticate(string username, string password)
{//TODO: remove error specifics like no user etc and turn it into "authentication failure" or similar

	//sql statements
	const string hash = "select saltedhash from users where username=$1";
	const string auth = "select count(*) from users where username=$1 and saltedhash=crypt($2, $3)";
	const string setsession = "update users set sessionid=$1 where username=$2";

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
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<unsigned long> dist (0, 9223372036854775807);
	long sessionid = dist(mt);
	try
	{
		dbconn.prepare("setsession", setsession);
		work setTimestamp(dbconn);
		setTimestamp.prepared("setsession")(sessionid)(username).exec();
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

void PGUtils::setFd(unsigned long sessionid, int fd, int which)
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
bool PGUtils::verifySessionid(unsigned long sessionid, int fd)
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

string PGUtils::userFromSessionid(unsigned long sessionid)
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

unsigned long PGUtils::userSessionId(string uname)
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

void PGUtils::killInstance()
{
	delete instance;
}


void PGUtils::insertLog(DBLog dbl)
{
	const string ins = "insert into logs (ts, tag, message, type, ip, who, relatedkey) values ($1, $2, $3, $4, $5, $6, $7)";
	dbconn.prepare("ins", ins);
	work wIns(dbconn);
	wIns.prepared("ins")(dbl.getTimestamp())(dbl.getTag())(dbl.getMessage())(dbl.getType())(dbl.getIp())(dbl.getUser())(dbl.getRelatedKey()).exec();
	wIns.commit();

	//use in memory hash table of tag id --> tag name so tag names only have to be written down once: in the db
	const string getTag = "select tagname from tag where tagid=$1";
	string tagString = "(tag)";
	int tagId = dbl.getTag();
	if(tagNames.count(tagId) == 0)
	{
		//only do the db lookup if necessary. should help performance
		dbconn.prepare("getTag", getTag);
		work wTag(dbconn);
		result dbresult = wTag.prepared("getTag")(tagId).exec();
		if(dbresult.size() > 0)
		{
			tagString = dbresult[0][0].as<string>();
			tagNames[tagId] = tagString;
		}
	}
	else
	{
		tagString = tagNames[tagId];
	}
	cout << tagString << ": " << dbl.getMessage() << "\n";
}




