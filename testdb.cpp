#include <iostream>
#include "pgutils.hpp"
#include "const.h"

using namespace std;

void interpretError(long err);
void interpretError(int err);

int main(int argc, char *argv[])
{
	cout << "Start testing login\n";
	PGUtils *test = PGUtils::getInstance();
	interpretError(test->authenticate("libprohibited", "feedme")); //correct log in
	interpretError(test->authenticate("libprohibited","asdf")); //wrong password
	interpretError(test->authenticate("nobody","asdf")); //non existant user

	cout << "\n";
	cout << "Start testing fd set\n";
	long sessionid = test->authenticate("libprohibited", "feedme");
	test->setFd(sessionid, 99, COMMAND); //right combination for command
	test->setFd(sessionid, 98, MEDIA); //right combination for media
	test->setFd(sessionid, 99, 100); //"which" fd non existant in const.h
	test->setFd(1, 100, COMMAND); //userid non existant
	test->setFd(1, 100, 100); //userid non existant and "which" fd not in const.h

	cout << "\n";
	cout << "Start testing seesion id verification\n";
	cout << "correct combo " << test->verifySessionid(sessionid, 99) <<"\n";
	cout << "wrong fd " << test->verifySessionid(sessionid, 5) << "\n";
	cout << "wrong sessionid " << test->verifySessionid(123, 99) << "\n";
	cout << "both wrong " << test->verifySessionid(1, 1) << "\n";

	cout << "\n";
	cout << "Start testing username lookup from command fd\n";
	cout << "Lookup Index: " << test->userFromFd(99, COMMAND) << "\n";
	cout << "Lookup nonexistant " << test->userFromFd(5, COMMAND) << "\n";

	cout << "\n";
	cout << "Start testing fd lookup from user name\n";
	cout << "Lookup command fd Index: " << test->userFd("libprohibited", COMMAND) << "\n";
	cout << "Lookup command fd Touma(not logged in): " << test->userFd("righthand", COMMAND) << "\n";
	cout << "Lookup command fd nonexistant " << test->userFd("nobody", COMMAND) << "\n";
	cout << "Lookup media fd Index: " << test->userFd("libprohibited", MEDIA) << "\n";
	cout << "Lookup media fd Touma(not logged in): " << test->userFd("righthand", MEDIA) << "\n";
	cout << "Lookup media fd nonexistant " << test->userFd("nobody", MEDIA) << "\n";

	cout << "\n";
	cout << "Start testing user exists\n";
	cout << "Query zapper: " << test->doesUserExist("zapper") << "\n";
	cout << "Query nobody: " << test->doesUserExist("nobody") << "\n";

	cout << "\n";
	cout << "Start testing clear session...\n";
	cin.get();
	test->clearSession("libprohibited");
	
	return 0;
}

void interpretError (long err)
{
	if(err > -1)
	{
		cout << "no error. everything went fine\n";
	}
	else if (err == EGENERIC)
	{
		cout << "generic unspecified error\n";
	}
	else if (err == ENOUSER)
	{
		cout << "user not in db\n";
	}
	else if (err == EPASS)
	{
		cout << "incorrect password\n";
	}
}

void interpretError (int err)
{
	if(err > -1)
	{
		cout << "no error. everything went fine\n";
	}
	else if (err == EGENERIC)
	{
		cout << "generic unspecified error\n";
	}
	else if (err == ENOUSER)
	{
		cout << "user not in db\n";
	}
	else if (err == EPASS)
	{
		cout << "incorrect password\n";
	}
}
