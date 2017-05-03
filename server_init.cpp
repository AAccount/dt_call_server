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

SSL_CTX* setupOpenSSL(string ciphers, string privateKeyFile, string publicKeyFile, string dhfile, UserUtils *userUtils, uint64_t initkey)
{
	//openssl setup
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	SSL_CTX *result = SSL_CTX_new(TLSv1_2_method());

	//set ssl properties
	if(result <= 0)
	{
		string error = "ssl initialization problem";
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return NULL;
	}

	//ciphers
	SSL_CTX_set_cipher_list(result, ciphers.c_str());

	//private key
	if(SSL_CTX_use_PrivateKey_file(result, privateKeyFile.c_str(), SSL_FILETYPE_PEM) <= 0)
	{
		string error = "problems with the private key";
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return NULL;
	}

	//public key
	if(SSL_CTX_use_certificate_file(result, publicKeyFile.c_str(), SSL_FILETYPE_PEM) <= 0)
	{
		string error = "problems with the public key";
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return NULL;
	}

	//dh params to make dhe ciphers work
	//https://www.openssl.org/docs/man1.0.1/ssl/SSL_CTX_set_tmp_dh.html
	DH *dh = NULL;
	FILE *paramfile;
	paramfile = fopen(dhfile.c_str(), "r");
	if(!paramfile)
	{
		string error = "problems opening dh param file at: " +  dhfile;
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return NULL;
	}
	dh = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
	fclose(paramfile);
	if(dh == NULL)
	{
		string error = "dh param file opened but openssl could not use dh param file at: " + dhfile;
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return NULL;
	}
	if(SSL_CTX_set_tmp_dh(result, dh) != 1)
	{
		string error = "dh param file opened and interpreted but reject by context: " + dhfile;
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return NULL;
	}
	//for ecdhe see SSL_CTX_set_tmp_ecdh
	return result;
}

void setupListeningSocket(struct timeval *timeout, int *fd, struct sockaddr_in *info, int port, UserUtils *userUtils, uint64_t initkey)
{
	//setup command port to accept new connections
	*fd = socket(AF_INET, SOCK_STREAM, 0); //tcp socket
	if(*fd < 0)
	{
		string error = "cannot establish socket";
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		exit(1);
	}
	bzero((char *) info, sizeof(struct sockaddr_in));
	info->sin_family = AF_INET;
	info->sin_addr.s_addr = INADDR_ANY; //listen on any nic
	info->sin_port = htons(port);
	if(bind(*fd, (struct sockaddr *)info, sizeof(struct sockaddr_in)) < 0)
	{
		string error = "cannot bind command socket to a nic";
		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		exit(1);
	}
	if(setsockopt(*fd, SOL_SOCKET, SO_RCVTIMEO, (char*)timeout, sizeof(struct timeval)) < 0)
	{
			string error = "cannot set command socket options";
	 		userUtils->insertLog(Log(TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
	 		perror(error.c_str());
	 		exit(1);
	}
	listen(*fd, MAXLISTENWAIT);
}
