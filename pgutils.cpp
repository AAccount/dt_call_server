#include <time.h>

#include <pqxx/pqxx>
#include <random>
#include <iostream>
#include <unordered_map> //hash table

#include "const.h"
#include "pgutils.hpp"
#include "Utils.hpp"
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

uint64_t PGUtils::authenticate(string username, string password, uint64_t relatedKey)
{
	const string hash = "select saltedhash from users where username=$1";
	const string auth = "select count(*) from users where username=$1 and saltedhash=crypt($2, $3)";
	const string setsession = "update users set sessionid=$1 where username=$2";

	try
	{
		//get the salted hash for verification
		dbconn.prepare("hash", hash);
		work getHash(dbconn);
		result resultHash = getHash.prepared("hash")(username).exec();
		getHash.commit();
		if(resultHash.size() < 1)
		{//no use continuing if the user doesn't exist
			uint64_t now = Utils::millisNow();
			string error = "user doesn't exist";
			insertLog(DBLog(now, TAG_POSTGRES_AUTH, error, SYSTEMLOG, relatedKey));
			return 0;
		}
		string saltedHash = resultHash[0][0].as<string>();

		//now authentiate the user against the db
		dbconn.prepare("auth", auth);
		work getAuth(dbconn);
		result resultAuth = getAuth.prepared("auth")(username)(password)(saltedHash).exec();
		getAuth.commit();
		if(resultAuth[0][0].as<int>() != 1)
		{
			uint64_t now = Utils::millisNow();
			string error = "wrong password";
			insertLog(DBLog(now, TAG_POSTGRES_AUTH, error, SYSTEMLOG, relatedKey));
			return 0;
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
		uniform_int_distribution<uint64_t> dist (0, (uint64_t)9223372036854775807);
		uint64_t sessionid = dist(mt);

		dbconn.prepare("setsession", setsession);
		work setTimestamp(dbconn);
		setTimestamp.prepared("setsession")(sessionid)(username).exec();
		setTimestamp.commit();
		return sessionid;

	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_AUTH, error, SYSTEMLOG, relatedKey));
		return 0;
	}
}

void PGUtils::setFd(uint64_t sessionid, int fd, int which, uint64_t relatedKey)
{
	const string setCmd = "update users set commandfd=$1 where sessionid=$2";
	const string setMedia = "update users set mediafd=$1 where sessionid=$2";

	try
	{
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
			uint64_t now = Utils::millisNow();
			string message = "parameter 'which' is invalid. given: " + to_string(which);
			insertLog(DBLog(now, TAG_POSTGRES_SETFD, message, SYSTEMLOG, relatedKey));
		}
	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_SETFD, error, SYSTEMLOG, relatedKey));
	}
}

void PGUtils::clearSession(string username, uint64_t relatedKey)
{
	const string clear = "update users set commandfd=NULL, mediafd=NULL, sessionid=NULL where username=$1";

	try
	{
		dbconn.prepare("clear", clear);
		work clearInfo(dbconn);
		clearInfo.prepared("clear")(username).exec();
		clearInfo.commit();
	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_CLEARSESS, error, SYSTEMLOG, relatedKey));
	}
}

bool PGUtils::verifySessionid(uint64_t sessionid, int fd, uint64_t relatedKey)
{
	const string verify = "select count(*) from users where commandfd=$1 and sessionid=$2";

	try
	{
		dbconn.prepare("verify", verify);
		work verifySessionid(dbconn);
		result dbresult = verifySessionid.prepared("verify")(fd)(sessionid).exec();
		verifySessionid.commit();
		if(dbresult[0][0].as<int>() == 1)
		{
			return true;
		}
		else
		{
			uint64_t now = Utils::millisNow();
			string message = to_string(sessionid) + " doesn't match anyone";
			insertLog(DBLog(now, TAG_POSTGRES_CLEARSESS, message, SYSTEMLOG, relatedKey));
		}
	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_CLEARSESS, error, SYSTEMLOG, relatedKey));
	}
	return false;
}

string PGUtils::userFromFd(int fd, int which, uint64_t relatedKey)
{//makes the assumption you verified the session id sent from this fd is valid
	try
	{
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
			else
			{
				uint64_t now = Utils::millisNow();
				string message = "nobody has command fd: " + to_string(fd);
				insertLog(DBLog(now, TAG_POSTGRES_UFROMFD, message, SYSTEMLOG, relatedKey));
			}
			return "";
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
			else
			{
				uint64_t now = Utils::millisNow();
				string message = "nobody has media fd: " + to_string(fd);
				insertLog(DBLog(now, TAG_POSTGRES_UFROMFD, message, SYSTEMLOG, relatedKey));
			}
			return "";
		}
		else
		{
			uint64_t now = Utils::millisNow();
			string message = "parameter 'which' is invalid. given: " + to_string(which);
			insertLog(DBLog(now, TAG_POSTGRES_UFROMFD, message, SYSTEMLOG, relatedKey));
			return "";
		}
	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_UFROMFD, error, SYSTEMLOG, relatedKey));
		return "";
	}
}

string PGUtils::userFromSessionid(uint64_t sessionid, uint64_t relatedKey)
{
	const string userFromSession = "select username from users where sessionid=$1";
	
	try
	{
		dbconn.prepare("userFromSession", userFromSession);
		work id2User(dbconn);
		result dbresult = id2User.prepared("userFromSession")(sessionid).exec();
		if(dbresult.size() > 0)
		{
			return dbresult[0][0].as<string>();
		}
		else
		{
			uint64_t now = Utils::millisNow();
			string message = to_string(sessionid) + " doesn't match anyone";
			insertLog(DBLog(now, TAG_POSTGRES_UFROMSESS, message, SYSTEMLOG, relatedKey));
		}
	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_UFROMSESS, error, SYSTEMLOG, relatedKey));
	}
	return "";
}

int PGUtils::userFd(string user, int which, uint64_t relatedKey)
{
	try
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
				return dbresult[0][0].as<int>();
			}
			else
			{
				uint64_t now = Utils::millisNow();
				string message = user + " doesn't have a command fd";
				insertLog(DBLog(now, TAG_POSTGRES_FDFROMU, message, SYSTEMLOG, relatedKey));
			}
			return 0;
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
				return dbresult[0][0].as<int>();
			}
			else
			{
				uint64_t now = Utils::millisNow();
				string message = user + " doesn't have a media fd";
				insertLog(DBLog(now, TAG_POSTGRES_FDFROMU, message, SYSTEMLOG, relatedKey));
			}
			return 0;
		}
		else
		{
			uint64_t now = Utils::millisNow();
			string message = "parameter 'which' is invalid. given: " + to_string(which);
			insertLog(DBLog(now, TAG_POSTGRES_FDFROMU, message, SYSTEMLOG, relatedKey));
			return 0;
		}
	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_FDFROMU, error, SYSTEMLOG, relatedKey));
		return 0;
	}
}

bool PGUtils::doesUserExist(string name, uint64_t relatedKey)
{
	const string queryUser = "select username from users where username=$1";

	try
	{
		dbconn.prepare("queryUser", queryUser);
		work wQueryUser(dbconn);
		result dbresult = wQueryUser.prepared("queryUser")(name).exec();
		wQueryUser.commit();
		if(dbresult.size() > 0)
		{
			return true;
		}
	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_UTHERE, error, SYSTEMLOG, relatedKey));
	}
	return false;
}

uint64_t PGUtils::userSessionId(string uname, uint64_t relatedKey)
{
	const string querySess = "select sessionid from users where username=$1";

	try
	{
		dbconn.prepare("querySess", querySess);
		work wQuerySess(dbconn);
		result dbresult = wQuerySess.prepared("querySess")(uname).exec();
		if(dbresult.size() > 0)
		{
			return dbresult[0][0].as<uint64_t>();
		}
		else
		{
			uint64_t now = Utils::millisNow();
			string message = uname + " doesn't have a session id";
			insertLog(DBLog(now, TAG_POSTGRES_SESSFROMU, message, SYSTEMLOG, relatedKey));
			return 0;
		}
	}
	catch(exception &e)
	{
		uint64_t now = Utils::millisNow();
		string error = e.what();
		insertLog(DBLog(now, TAG_POSTGRES_SESSFROMU, error, SYSTEMLOG, relatedKey));
		return 0;
	}
}

void PGUtils::killInstance()
{
	delete instance;
}


void PGUtils::insertLog(DBLog dbl)
{
	const string ins = "insert into logs (ts, tag, message, type, ip, who, relatedkey) values ($1, $2, $3, $4, $5, $6, $7)";

	try
	{
	dbconn.prepare("ins", ins);
	work wIns(dbconn);
	wIns.prepared("ins")(dbl.getTimestamp())(dbl.getTag())(dbl.getMessage())(dbl.getType())(dbl.getIp())(dbl.getUser())(dbl.getRelatedKey()).exec();
	wIns.commit();
	}
	catch (exception &e)
	{
		//if logging to the db failed all you can do is print to stdout. not like you can log a db fail to the db
		cout << "db logging failed because: " << e.what();
		cout << "problem log: " << dbl;
	}

	//use in memory hash table of tag id --> tag name so tag names only have to be written down once: in the db
	const string getTag = "select tagname from tag where tagid=$1";
	string tagString = "(tag)";
	int tagId = dbl.getTag();
	if(tagNames.count(tagId) == 0)
	{
		try
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
		catch(exception &e)
		{
			//nothing useful that can be done. the tag name is just for stdout use. no harm if it can't be found
			cout << "something failed in tag lookup: " << e.what();
		}
	}
	else
	{
		tagString = tagNames[tagId];
	}
	cout << tagString << ": " << dbl.getMessage() << "\n";
}
