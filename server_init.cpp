/*
 * server_init.c
 *
 *  Created on: May 2, 2017
 *      Author: Daniel
 *
 *  Various intialization functions used by the server.
 *  Moved here for readability.
 */
#include "server_init.hpp"

using namespace std;

void readServerConfig(int *cmdPort, int *mediaPort, string *publicKeyFile, string *privateKeyFile, string *ciphers, string *dhfile, UserUtils *userUtils, uint64_t initkey)
{
	ifstream conffile(CONFFILE);
	string line;
	bool gotPublicKey = false, gotPrivateKey = false, gotCiphers = false, gotCmdPort = false, gotMediaPort = false, gotDhFile = false;

	while(getline(conffile, line))
	{
		//skip blank lines and comment lines
		if(line.length() == 0 || line.at(0) == '#')
		{
			continue;
		}

		//read the variable and its value
		string var, value;
		stringstream ss(line);
		getline(ss, var, '=');
		getline(ss, value, '=');

		//cleanup the surrounding whitespace and strip the end of line comment
		var = Utils::trim(var);
		value = Utils::trim(value);

		//if there is no value then go on to the next line
		if(value == "")
		{
			continue;
		}

		if(var == "command")
		{
			*cmdPort = atoi(value.c_str());
			gotCmdPort = true;
			continue;
		}
		else if (var == "media")
		{
			*mediaPort = atoi(value.c_str());
			gotMediaPort = true;
			continue;
		}
		else if (var == "public")
		{
			*publicKeyFile = value;
			gotPublicKey = true;
			continue;
		}
		else if (var == "private")
		{
			*privateKeyFile = value;
			gotPrivateKey = true;
			continue;
		}
		else if (var == "ciphers")
		{
			*ciphers = value;
			gotCiphers = true;
			continue;
		}
		else if (var == "dhfile")
		{
			*dhfile = value;
			gotDhFile = true;
			continue;
		}
		else
		{
			string unknown = "unknown variable parsed: " + line;
			userUtils->insertLog(Log(TAG_INIT, unknown, SELF, SYSTEMLOG, SELFIP, initkey));
		}
	}

	//at the minimum a public and private key must be specified. everything else has a default value
	if (!gotPublicKey || !gotPrivateKey || !gotDhFile)
	{
		string conffile = CONFFILE;
		if(!gotPublicKey)
		{
			string error = "Your did not specify a PUBLIC key pem in: " + conffile + "\n";
			userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		}
		if(!gotPublicKey)
		{
			string error = "Your did not specify a PRIVATE key pem in: " + conffile + "\n";
			userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		}
		if(!gotDhFile)
		{
			string error = "Your did not specify a DH file for DHE ciphers in: " + conffile + "\n";
			userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		}
		exit(1);
	}

	//warn of default values if they're being used
	if(!gotCmdPort)
	{
		string message =  "Using default command port of: " + to_string(*cmdPort);
		userUtils->insertLog(Log(TAG_INIT, message, SELF, SYSTEMLOG, SELFIP, initkey));
	}
	if(!gotMediaPort)
	{
		string message= "Using default media port of: " + to_string(*mediaPort);
		userUtils->insertLog(Log(TAG_INIT, message, SELF, SYSTEMLOG, SELFIP, initkey));
	}
	if(!gotCiphers)
	{
		string message = "Using default ciphers (no ECDHE): " + *ciphers;
		userUtils->insertLog(Log(TAG_INIT, message, SELF, SYSTEMLOG, SELFIP, initkey));
	}

}
