#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/time.h> 
#include <sys/select.h>
#include <netinet/in.h>
#include <signal.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "const.h"
#include "server.hpp"
#include "pgutils.hpp"
#include "dblog.hpp"
#include "Utils.hpp"

#include <cmath>
#include <iostream>
#include <string>
#include <unordered_map> //hash table
#include <map> //self balancing tree used as a table
#include <vector>
#include <fstream>
#include <random>

using namespace std;

//using goto in general to avoid excessive indentation and else statements

//information on what each socket descriptor is (command, media) and what it's supposed to be doing if it's a media socket
unordered_map<int, int> sdinfo; 

//associates socket descriptors to their ssl structs
map<int, SSL*>clientssl;

//fail counts of each socket descriptor. if there are too many fails then remove the socket.
//most likely to be used by media sockets during calls. media socket gets reset after a call anyways
//so any fails are going to come from the current call
unordered_map<int, int> failCount;

int main(int argc, char *argv[])
{
	//setup random number generator for the log relation key (a random number that related logs can use)
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<uint64_t> dist (0, (uint64_t)9223372036854775807);
	uint64_t initkey = dist(mt);

	//you MUST establish the postgres utilities instance variable here or get a segmentation inside on c->prepare
	PGUtils *postgres = PGUtils::getInstance();

	postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, "starting call operator", SELF, SYSTEMLOG, SELFIP, initkey));

#ifdef JSTOPMEDIA
	postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, "compiled with JSTOPMEDIA flag", SELF, SYSTEMLOG , SELFIP, initkey));
#endif
	
	int cmdFD, incomingCmd, cmdPort = DEFAULTCMD; //command port stuff
	int mediaFD, incomingMedia, mediaPort = DEFAULTMEDIA, bufferRead; //media port stuff
	int returnValue; //error handling
	int maxsd, sd; //select related vars
	SSL *sdssl; //used for iterating through the ordered map
	socklen_t clilen;

	char inputBuffer[BUFFERSIZE+1];

	//read program options from a config file
	bool gotPublicKey = false, gotPrivateKey = false, gotCiphers = false, gotCmdPort = false, gotMediaPort = false, gotDhFile = false;
	string publicKeyFile;
	string privateKeyFile;
	string ciphers = DEFAULTCIPHERS;
	string dhfile = "";

	ifstream conffile(CONFFILE);
	string line;

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
		var = trim(var);
		value = trim(value);

		//if there is no value then go on to the next line
		if(value == "")
		{
			continue;
		}

		if(var == "command")
		{
			cmdPort = atoi(value.c_str());
			gotCmdPort = true;
			continue;
		}
		else if (var == "media")
		{
			mediaPort = atoi(value.c_str());
			gotMediaPort = true;
			continue;
		}
		else if (var == "public")
		{
			publicKeyFile = value;
			gotPublicKey = true;
			continue;
		}
		else if (var == "private")
		{
			privateKeyFile = value;
			gotPrivateKey = true;
			continue;
		}
		else if (var == "ciphers")
		{
			ciphers = value;
			gotCiphers = true;
			continue;
		}
		else if (var == "dhfile")
		{
			dhfile = value;
			gotDhFile = true;
			continue;
		}
		else
		{
			string unknown = "unknown variable parsed: " + line;
			postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, unknown, SELF, SYSTEMLOG, SELFIP, initkey));
		}
	}

	//at the minimum a public and private key must be specified. everything else has a default value
	if (!gotPublicKey || !gotPrivateKey || !gotDhFile)
	{
		string conffile = CONFFILE;
		if(!gotPublicKey)
		{
			string error = "Your did not specify a PUBLIC key pem in: " + conffile + "\n";
			postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		}
		if(!gotPublicKey)
		{
			string error = "Your did not specify a PRIVATE key pem in: " + conffile + "\n";
			postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		}
		if(!gotDhFile)
		{
			string error = "Your did not specify a DH file for DHE ciphers in: " + conffile + "\n";
			postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		}
		exit(1);
	}

	//warn of default values if they're being used
	if(!gotCmdPort)
	{
		string message =  "Using default command port of: " + to_string(cmdPort);
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, message, SELF, SYSTEMLOG, SELFIP, initkey));
	}
	if(!gotMediaPort)
	{
		string message= "Using default media port of: " + to_string(mediaPort);
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, message, SELF, SYSTEMLOG, SELFIP, initkey));
	}
	if(!gotCiphers)
	{
		string message = "Using default ciphers (no ECDHE): " + ciphers;
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, message, SELF, SYSTEMLOG, SELFIP, initkey));
	}

	struct sockaddr_in serv_cmd, serv_media, cli_addr;
	fd_set readfds;
	fd_set writefds;

	//openssl setup
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	//set ssl properties
	SSL_CTX *sslcontext = SSL_CTX_new(TLSv1_2_method());
	if(&sslcontext <= 0)
	{
		string error = "ssl initialization problem";
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}

	//ciphers
	SSL_CTX_set_cipher_list(sslcontext, ciphers.c_str());

	//private key
	returnValue= SSL_CTX_use_PrivateKey_file(sslcontext, privateKeyFile.c_str(), SSL_FILETYPE_PEM);
	if(returnValue <= 0)
	{
		string error = "problems with the private key";
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}

	//public key
	returnValue = SSL_CTX_use_certificate_file(sslcontext, publicKeyFile.c_str(), SSL_FILETYPE_PEM);
	if(returnValue <= 0)
	{
		string error = "problems with the public key";
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}

	//dh params to make dhe ciphers work
	//https://www.openssl.org/docs/man1.0.1/ssl/SSL_CTX_set_tmp_dh.html
	DH *dh = NULL;
	FILE *paramfile;
	paramfile = fopen(dhfile.c_str(), "r");
	if(!paramfile)
	{
		string error = "problems opening dh param file at: " + dhfile;
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}
	dh = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
	fclose(paramfile);
	if(dh == NULL)
	{
		string error = "dh param file opened but openssl could not use dh param file at: " + dhfile;
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}
	returnValue = SSL_CTX_set_tmp_dh(sslcontext, dh);
	if(returnValue != 1)
	{
		string error = "dh param file opened and interpreted but reject by context: " + dhfile;
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}
	//for ecdhe see SSL_CTX_set_tmp_ecdh

	//socket read timeout option
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = READTIMEOUT;

	//setup command port to accept new connections
	cmdFD = socket(AF_INET, SOCK_STREAM, 0); //tcp socket
	if(cmdFD < 0)
	{
		string error = "cannot establish command socket";
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}
	bzero((char *) &serv_cmd, sizeof(serv_cmd));
	serv_cmd.sin_family = AF_INET;
	serv_cmd.sin_addr.s_addr = INADDR_ANY; //listen on any nic
	serv_cmd.sin_port = htons(cmdPort);
	returnValue = bind(cmdFD, (struct sockaddr *) &serv_cmd, sizeof(serv_cmd)); //bind socket to nic and port
	if(returnValue < 0)
	{
		string error = "cannot bind command socket to a nic";
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}
	returnValue = setsockopt(cmdFD, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	if(returnValue < 0)
	{
			string error = "cannot set command socket options";
	 		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
	 		perror(error.c_str());
	 		return 1;
	}
	listen(cmdFD, MAXLISTENWAIT);

	//setup media port to accept new connections
	mediaFD = socket(AF_INET, SOCK_STREAM, 0); //tcp socket
	if(mediaFD < 0)
	{
		string error = "cannot establish media socket";
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}
	bzero((char *) &serv_media, sizeof(serv_media));
	serv_media.sin_family = AF_INET;
	serv_media.sin_addr.s_addr = INADDR_ANY; //listen on any nic
	serv_media.sin_port = htons(mediaPort);
	returnValue = bind(mediaFD, (struct sockaddr *) &serv_media, sizeof(serv_media)); //bind socket to nic and port
	if(returnValue < 0)
	{
		string error = "cannot bind media socket to a nic";
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
		perror(error.c_str());
		return 1;
	}
	returnValue = setsockopt(mediaFD, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	if(returnValue < 0)
	{
			string error = "cannot set media socket options";
	 		postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
	 		perror(error.c_str());
	 		return 1;
	}
	listen(mediaFD, MAXLISTENWAIT);

	clilen = sizeof(cli_addr);

	//sigpipe is thrown for closing the broken connection. it's gonna happen for a voip server handling mobile clients
	//what're you gonna do about it... IGNORE IT!!
	signal(SIGPIPE, SIG_IGN);

	//write select timeout
	struct timeval writeTimeout;
	writeTimeout.tv_sec = 0;
	writeTimeout.tv_usec = WSELECTTIMEOUT;

	while(true) //forever
	{
#ifdef VERBOSE
		cout << "------------------------------------------\n----------------------------------------\n";
#endif
		FD_ZERO(&readfds);
		FD_SET(cmdFD, &readfds);
		FD_SET(mediaFD, &readfds);
		FD_ZERO(&writefds);
		maxsd = (cmdFD > mediaFD) ? cmdFD : mediaFD; //quick 1 liner for determining the bigger sd

		//http://www.cplusplus.com/reference/map/map/begin/
		map<int, SSL*>::iterator it;
		for(it = clientssl.begin(); it != clientssl.end(); ++it)
		{
			sd = it->first;			
			FD_SET(sd, &readfds);
			FD_SET(sd, &writefds);
			if(sd > maxsd)
			{
				maxsd = sd;
			}
		}

		//wait for somebody to send something to the server
		returnValue = select(maxsd+1, &readfds, NULL, NULL, NULL);
		if(returnValue < 0)
		{
			string error = "read fds select system call error";
			postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
			perror(error.c_str());
			return 1;
		}
#ifdef VERBOSE
		cout << "select has " << returnValue << " sockets ready for reading\n";
#endif
		//now that someone has sent something, check all the sockets to see which ones are writable
		//give a 0.1ms time to check. don't want the request to involve an unwritable socket and
		//stall the whole server
		returnValue = select(maxsd+1, NULL, &writefds, NULL, &writeTimeout);
		if(returnValue < 0)
		{
			string error = "write fds select system call error";
			postgres->insertLog(DBLog(Utils::millisNow(), TAG_INIT, error, SELF, ERRORLOG, SELFIP, initkey));
			perror(error.c_str());
			return 1;
		}
#ifdef VERBOSE
		cout << "select has " << returnValue << " sockets ready for writing\n";
#endif
		//check for a new incoming connection on command port
		if(FD_ISSET(cmdFD, &readfds))
		{
			uint64_t relatedKey = dist(mt);

			incomingCmd = accept(cmdFD, (struct sockaddr *) &cli_addr, &clilen);
			if(incomingCmd < 0)
			{
				string error = "accept system call error";
				postgres->insertLog(DBLog(Utils::millisNow(), TAG_INCOMINGCMD, error, SELF, ERRORLOG, DONTKNOW, relatedKey));
				perror(error.c_str());
				goto skipNewCmd;
			}
			string ip = inet_ntoa(cli_addr.sin_addr);

			//if this socket has problems in the future, give it 1sec to get its act together or giveup on that operation
			returnValue = setsockopt(incomingCmd, SOL_SOCKET, SO_RCVTIMEO, (char*) &timeout, sizeof(timeout));
			if(returnValue < 0)
			{
				string error = "cannot set timeout for incoming media socket from " + ip;
				postgres->insertLog(DBLog(Utils::millisNow(), TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip, relatedKey));
				perror(error.c_str());
				shutdown(incomingMedia, 2);
				close(incomingMedia);
				goto skipNewMedia;
			}

			//setup ssl connection
			SSL *connssl = SSL_new(sslcontext);
			SSL_set_fd(connssl, incomingCmd);
			returnValue = SSL_accept(connssl);

			//in case something happened before the incoming connection can be made ssl.
			if(returnValue <= 0)
			{
				string error = "Problem initializing new command tls connection from " + ip;
				postgres->insertLog(DBLog(Utils::millisNow(), TAG_INCOMINGCMD, error, SELF, ERRORLOG, ip, relatedKey));
				SSL_shutdown(connssl);
				SSL_free(connssl);
				shutdown(incomingCmd, 2);
				close(incomingCmd);
			}
			else
			{
				//add the new socket descriptor to the client self balancing tree
				string message = "new command socket from " + ip;
				postgres->insertLog(DBLog(Utils::millisNow(), TAG_INCOMINGCMD, message, SELF, INBOUNDLOG, ip, relatedKey));
				clientssl[incomingCmd] = connssl;
				sdinfo[incomingCmd] = SOCKCMD;
				failCount[incomingCmd] = 0;
			}
		}
		skipNewCmd:;

		//check for a new incoming connection on media port
		if(FD_ISSET(mediaFD, &readfds))
		{
			uint64_t relatedKey = dist(mt);

			incomingMedia = accept(mediaFD, (struct sockaddr *) &cli_addr, &clilen);
			if(incomingMedia < 0)
			{
				string error = "accept system call error";
				postgres->insertLog(DBLog(Utils::millisNow(), TAG_INCOMINGMEDIA, error, SELF, ERRORLOG, DONTKNOW, relatedKey));
				perror(error.c_str());
				goto skipNewMedia;
			}
			string ip = inet_ntoa(cli_addr.sin_addr);

			//if this socket has problems in the future, give it 1sec to get its act together or giveup on that operation
			returnValue = setsockopt(incomingMedia, SOL_SOCKET, SO_RCVTIMEO, (char*) &timeout, sizeof(timeout));
			if(returnValue < 0)
			{
				string error = "cannot set timeout for incoming media socket from " + ip;
				postgres->insertLog(DBLog(Utils::millisNow(), TAG_INCOMINGMEDIA, error, SELF, ERRORLOG, ip, relatedKey));
				perror(error.c_str());
				shutdown(incomingMedia, 2);
				close(incomingMedia);
				goto skipNewMedia;
			}

			SSL *connssl = SSL_new(sslcontext);
			SSL_set_fd(connssl, incomingMedia);
			returnValue = SSL_accept(connssl);

			//in case something happened before the incoming connection can be made ssl
			if(returnValue <= 0)
			{
				string error = "Problem initializing new command tls connection from " + ip;
				postgres->insertLog(DBLog(Utils::millisNow(), TAG_INCOMINGMEDIA, error, SELF, ERRORLOG, ip, relatedKey));
				SSL_shutdown(connssl);
				SSL_free(connssl);
				shutdown(incomingMedia, 2);
				close(incomingMedia);
			}
			else
			{
				string message = "new media socket from " + ip;
				postgres->insertLog(DBLog(Utils::millisNow(), TAG_INCOMINGMEDIA, message, SELF, INBOUNDLOG, ip, relatedKey));
				clientssl[incomingMedia] = connssl;
				sdinfo[incomingMedia] = SOCKMEDIANEW;
				failCount[incomingMedia] = 0;
			}
		}
		skipNewMedia:;

		//check for data on an existing connection
		//reuse the same iterator variable (reinitialize it too)
		vector<int> removals;
		for(it = clientssl.begin(); it != clientssl.end(); ++it)
		{//figure out if it's a command, or voice data. handle appropriately

			//get the socket descriptor and associated ssl struct from the iterator round
			sd = it->first;
			sdssl = it->second;
			if(FD_ISSET(sd, &readfds))
			{
#ifdef VERBOSE
				cout << "socket descriptor: " << sd << " was marked as set\n";
#endif
				//when a client disconnects, for some reason, the socket is marked as having "stuff" on it.
				//however that "stuff" is no good for ssl, so use eventful boolean to indicate if there was
				//any ssl work done for this actively marked socket descriptor. if not, drop the socket.
				bool waiting = true;
				uint64_t iterationKey = dist(mt);

				//read from the socket into the buffer
				bufferRead = 0;
				bzero(inputBuffer, BUFFERSIZE+1);
				do
				{//wait for the input chunk to come in first before doing something
					returnValue = SSL_read(sdssl, inputBuffer, BUFFERSIZE-bufferRead);
					if(returnValue > 0)
					{
						bufferRead = bufferRead + returnValue;
					}
					int sslerr = SSL_get_error(sdssl, returnValue);
					switch (sslerr)
					{
						case SSL_ERROR_NONE:
							waiting = false;
							break;
						//other cases when necessary. right now only no error signals a successful read
					}
				} while(waiting && SSL_pending(sdssl));

				///SSL_read return 0 = dead socket
				if(returnValue == 0)
				{
					string user;
					if(sdinfo[sd] == SOCKCMD)
					{
						user = postgres->userFromFd(sd, COMMAND, iterationKey);
					}
					else
					{
						user = postgres->userFromFd(sd, MEDIA, iterationKey);
					}
					string ip = ipFromSd(sd);
					string error = "socket has died";
					postgres->insertLog(DBLog(Utils::millisNow(), TAG_DEADSOCK, error, user, ERRORLOG, ip, iterationKey));
					removals.push_back(sd);
					goto skipfd;
				}

				int sdstate = sdinfo[sd];
				if(sdstate == SOCKCMD)
				{
					//what was previously a workaround now has an official purpose: heartbeat/ping ignore byte
					//this byte is just sent to keep the socket and its various nat tables it takes to get here alive
					string bufferString(inputBuffer);
					if(bufferString == JBYTE)
					{
#ifdef VERBOSE
						cout << "Got a " << JBYTE << " cap for media sd " << sd << "\n";
#endif
						goto skipfd;
					}
					string originalBufferCmd = to_string(inputBuffer); //save original command string before it gets mutilated by strtok
					vector<string> commandContents = parse(inputBuffer);
					string ip = ipFromSd(sd);
					time_t now = time(NULL);

					try
					{
						string command = commandContents.at(1);
						uint64_t timestamp = (uint64_t)stoull(commandContents.at(0)); //catch is for this
						uint64_t maxError = 60*MARGIN_OF_ERROR;
						uint64_t timeDifference = (uint64_t)std::llabs(now - timestamp);
						if(timeDifference > maxError)
						{
							//only bother processing the command if the timestamp was valid

							//prepare the error log
							uint64_t mins = timeDifference/60;
							uint64_t seconds = timeDifference - mins*60;
							string error = "command received was outside the "+to_string(MARGIN_OF_ERROR)+" minute margin of error: " + to_string(mins)+"mins, "+to_string(seconds) + "seconds";
							string user = postgres->userFromFd(sd, COMMAND, iterationKey);
							if(originalBufferCmd.find("login") == string::npos)
							{//don't accidentally leak passwords for bad login timestamps
								error = error + " (" + originalBufferCmd + ")";
							}
							else
							{
								error = error + commandContents.at(0) + "|login|" + user + "|????????"; //never store plain text passwords ANYWHERE
							}
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

							//send the rejection to the client
							string invalid = to_string(now) + "|resp|invalid|command\n";
							write2Client(invalid, sdssl, iterationKey);
							goto invalidcmd;
						}

						if(command == "login") //you can do string comparison like this in c++
						{//timestamp|login|username|passwd
							string username = commandContents.at(2);
							string plaintext = commandContents.at(3);
							string ip = ipFromSd(sd);
							string censoredInput = commandContents.at(0) + "|login|" + username + "|????????"; //never store plain text passwords ANYWHERE
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_LOGIN, censoredInput, username, INBOUNDLOG, ip, iterationKey));

							int oldcmd = postgres->userFd(username, COMMAND, iterationKey);
							if(oldcmd > 0)
							{//remove old SSL structs to prevent memory leak
#ifdef VERBOSE
								cout << "previous command socket/SSL* exists, will remove\n";
#endif
								removals.push_back(oldcmd);
							}

							int oldmedia = postgres->userFd(username, MEDIA, iterationKey);
							if(oldmedia > 0)
							{//remove old SSL structs to prevent memory leak
#ifdef VERBOSE
								cout << "previous meida socket/SSL* exists, will remove\n";
#endif
								removals.push_back(oldmedia);
							}

							uint64_t sessionid = postgres->authenticate(username, plaintext, iterationKey);
							if(sessionid == 0)
							{
								//for the user however, give no hints about what went wrong in case of brute force
								string invalid = to_string(now) + "|resp|invalid|command\n";
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_LOGIN, invalid, username, OUTBOUNDLOG, ip, iterationKey));
								write2Client(invalid, sdssl, iterationKey);
								goto invalidcmd;
							}

							//record a succesful login and response sent
							postgres->setFd(sessionid, sd, COMMAND, iterationKey);
							string resp = to_string(now) + "|resp|login|" + to_string(sessionid);
							write2Client(resp, sdssl, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_LOGIN, resp, username, OUTBOUNDLOG, ip, iterationKey));
						}

						//variables written from touma calling zapper perspective
						//command will come from touma's cmd fd
						else if (command == "call")
						{//timestamp|call|zapper|toumaid

							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string zapper = commandContents.at(2);
							string touma = postgres->userFromSessionid(sessionid, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, originalBufferCmd, touma, INBOUNDLOG, ip, iterationKey));

							if(!postgres->verifySessionid(sessionid, sd, iterationKey))
							{
								string error = " INVALID SESSION ID. refusing to start call";
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, error, touma, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, invalid, touma, OUTBOUNDLOG, ip, iterationKey));
								goto invalidcmd;
							}

							//double check touma has a mediafd
							int toumaMediaFd = postgres->userFd(touma, MEDIA, iterationKey);
							if(toumaMediaFd == 0)
							{
								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, invalid, touma, OUTBOUNDLOG, ip, iterationKey));
								goto invalidcmd;
							}

							//find out if zapper has both a command and media fd
							int zapperMediaFd = postgres->userFd(zapper, MEDIA, iterationKey);
							int zapperCmdFd = postgres->userFd(zapper, COMMAND, iterationKey);
							if(zapperMediaFd == 0 || zapperCmdFd == 0 )
							{
								string na = to_string(now) + "|ring|notavailable|" + zapper;
								write2Client(na, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, na, touma, OUTBOUNDLOG, ip, iterationKey));
								goto invalidcmd; //while not really an invalid command, there's no point of continuing
							}

							//make sure zapper isn't already in a call
							int currentState = sdinfo[zapperMediaFd];
							if(currentState != SOCKMEDIAIDLE)
							{
								string busy = to_string(now) + "|ring|busy|" + zapper;
								write2Client(busy, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, busy, touma, OUTBOUNDLOG, ip, iterationKey));
								goto invalidcmd; //not really invalid either but can't continue any further at this point
							}

							//make sure touma didn't accidentally dial himself
							if(touma == zapper)
							{
								string busy = to_string(now) + "|ring|busy|" + zapper; //ye olde landline did this
								write2Client(busy, sdssl, iterationKey);
								busy = "(self dialed) " + busy;
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, busy, touma, OUTBOUNDLOG, ip, iterationKey));
								goto invalidcmd; //not really invalid either but can't continue any further at this point
							}

							//setup the media fd statuses
							sdinfo[zapperMediaFd] = -toumaMediaFd;
							sdinfo[toumaMediaFd] = -zapperMediaFd;

							//tell touma that zapper is being rung
							string notifyTouma = to_string(now) + "|ring|available|" + zapper;
							write2Client(notifyTouma, sdssl, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, notifyTouma, touma, OUTBOUNDLOG, ip, iterationKey));
			
							//tell zapper touma wants to call her
							string notifyZapper = to_string(now) + "|ring|incoming|" + touma;
							SSL *zapperssl = clientssl[zapperCmdFd];
							write2Client(notifyZapper, zapperssl, iterationKey);
							string zapperip = ipFromSd(zapperCmdFd);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_CALL, notifyZapper, zapper, OUTBOUNDLOG, ip, iterationKey));
						}
						else if (command == "lookup")
						{
							string who = commandContents.at(2);
							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string from = postgres->userFromSessionid(sessionid, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_LOOKUP, originalBufferCmd, from, INBOUNDLOG, ip, iterationKey));

							if(!postgres->verifySessionid(sessionid, sd, iterationKey))
							{
								string error = "invalid sessionid attempting to do a user lookup";
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_LOOKUP, error, from, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_LOOKUP, invalid, from, OUTBOUNDLOG, ip, iterationKey));
								goto invalidcmd;
							}
							string exists = (postgres->doesUserExist(who, iterationKey)) ? "exists" : "doesntexist";
							string resp = to_string(now) + "|lookup|" + who + "|" + exists;
							write2Client(resp, sdssl, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_LOOKUP, resp, from, OUTBOUNDLOG, ip, iterationKey));
						}

						//variables written when zapper accepets touma's call
						//command will come from zapper's cmd fd
						else if (command == "accept")
						{//timestamp|accept|touma|zapperid
							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string zapper = postgres->userFromSessionid(sessionid, iterationKey);
							string touma = commandContents.at(2);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_ACCEPT, originalBufferCmd, zapper, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(zapper, touma, iterationKey))
							{
								string error = touma + " never made a call request to " + zapper;
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_ACCEPT, error, zapper, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_ACCEPT, invalid, zapper, OUTBOUNDLOG, ip , iterationKey));
								goto invalidcmd;
							}

							int zapperMediaFd = postgres->userFd(zapper, MEDIA, iterationKey);
							int toumaMediaFd = postgres->userFd(touma, MEDIA, iterationKey);
							sdinfo[zapperMediaFd] = toumaMediaFd;
							sdinfo[toumaMediaFd] = zapperMediaFd;

							//tell touma zapper accepted his call request										
							//	AND confirm to touma, it's zapper he's being connected with
							int toumaCmdFd = postgres->userFd(touma, COMMAND, iterationKey);
							SSL *toumaCmdSsl = clientssl[toumaCmdFd];
							string toumaResp = to_string(now) + "|call|start|" + zapper;
							write2Client(toumaResp, toumaCmdSsl, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_ACCEPT, toumaResp, touma, OUTBOUNDLOG, ipFromSd(toumaCmdFd), iterationKey));

							//confirm to zapper she's being connected to touma
							string zapperResp = to_string(now) + "|call|start|" + touma;
							write2Client(zapperResp, sdssl, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_ACCEPT, zapperResp, zapper, OUTBOUNDLOG, ip, iterationKey));
						}

						//variables modeled after setup touma calling zapper for easier readability
						//reject command would come from zapper's cmd fd
						else if (command == "reject")
						{//timestamp|reject|touma|sessionid
							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string zapper = postgres->userFromSessionid(sessionid, iterationKey);
							string touma = commandContents.at(2);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_REJECT, originalBufferCmd, zapper, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(zapper, touma, iterationKey))
							{
								string error = touma + " never made a call request to " + zapper;
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_REJECT, error, zapper, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_REJECT, invalid, zapper, OUTBOUNDLOG, ip , iterationKey));
								goto invalidcmd;
							}

							//set touma's and zapper's media socket state back to idle
							int toumaMediaFd = postgres->userFd(touma, MEDIA, iterationKey);
							int zapperMediaFd = postgres->userFd(zapper, MEDIA, iterationKey);
							sdinfo[toumaMediaFd] = SOCKMEDIAIDLE;
							sdinfo[zapperMediaFd] = SOCKMEDIAIDLE;

							//tell touma his call was rejected
							int toumaCmdFd = postgres->userFd(touma, COMMAND, iterationKey);
							SSL *toumaCmdSsl = clientssl[toumaCmdFd];
							string resp = to_string(now) + "|call|reject|" + zapper;
							write2Client(resp, toumaCmdSsl, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_REJECT, resp, touma, OUTBOUNDLOG, ipFromSd(toumaCmdFd), iterationKey));
						}

						//variables modeled after setup touma calling zapper for easier readability
						//end could come from either of them
						else if (command == "end")
						{
							//timestamp|end|touma|zappersid : zapper wants to end the call with touma
							//timestamp|end|zapper|toumasid : touma wants to end the call with zapper

							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string wants2End = postgres->userFromSessionid(sessionid, iterationKey);
							string stillTalking = commandContents.at(2);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_END, originalBufferCmd, wants2End, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(wants2End, stillTalking, iterationKey))
							{
								string error = stillTalking + " isn't in a call with " + wants2End;
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_END, error, wants2End, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_END, invalid, wants2End, OUTBOUNDLOG, ip, iterationKey));
								goto invalidcmd;
							}

							//set touma's and zapper's media socket state back to idle
							int endMediaFd = postgres->userFd(wants2End, MEDIA, iterationKey);
							int talkingMediaFd = postgres->userFd(stillTalking, MEDIA, iterationKey);
							sdinfo[endMediaFd] = SOCKMEDIAIDLE;
							sdinfo[talkingMediaFd] = SOCKMEDIAIDLE;

							//tell the one still talking, it's time to hang up
							string resp = to_string(now) + "|call|end|" + wants2End;
							int talkingCmdFd = postgres->userFd(stillTalking, COMMAND, iterationKey);
							SSL *talkingCmdSsl = clientssl[talkingCmdFd];
							write2Client(resp, talkingCmdSsl, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_END, resp, stillTalking, OUTBOUNDLOG, ipFromSd(talkingCmdFd), iterationKey));
						}
						//call timeout: zapper hasn't answer touma's call request in the 1 minute ring time
						//cancel the call... YOU MUST tell the server the call is cancelled so it can reset the media fd states
						//nothing has to be sent to touma because his phone will automatically take care of itself
						//	to back back to the home screen
						else if(command =="timeout")
						{
							string zapper = commandContents.at(2);
							uint64_t sessionid = (uint64_t)stoull(commandContents.at(3));
							string touma = postgres->userFromSessionid(sessionid, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_TIMEOUT, originalBufferCmd, touma, INBOUNDLOG, ip, iterationKey));

							if(!isRealCall(touma, zapper, iterationKey))
							{
								string error = touma + " never called " + zapper + " so there is nothing to timeout";
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_TIMEOUT, error, touma, ERRORLOG, ip, iterationKey));

								string invalid = to_string(now) + "|resp|invalid|command\n";
								write2Client(invalid, sdssl, iterationKey);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_TIMEOUT, invalid, touma, OUTBOUNDLOG, ip, iterationKey));
								goto invalidcmd;
							}

							//set touma's and zapper's media socket state back to idle
							int toumaMediaFd = postgres->userFd(touma, MEDIA, iterationKey);
							int zapperMediaFd = postgres->userFd(zapper, MEDIA, iterationKey);
							sdinfo[toumaMediaFd] = SOCKMEDIAIDLE;
							sdinfo[zapperMediaFd] = SOCKMEDIAIDLE;

							//tell zapper that time's up for answering touma's call
							string resp = to_string(now) + "|ring|timeout|" + touma;
							int zapperCmdFd = postgres->userFd(zapper, COMMAND, iterationKey);
							SSL *zapperCmdSsl = clientssl[zapperCmdFd];
							write2Client(resp, zapperCmdSsl, iterationKey);
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_TIMEOUT, resp, zapper, OUTBOUNDLOG, ipFromSd(zapperCmdFd), iterationKey));
						}
						else //commandContents[1] is not a known command... something fishy???
						{
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_BADCMD, originalBufferCmd, postgres->userFromFd(sd, COMMAND, iterationKey), INBOUNDLOG, ip, iterationKey));
						}
					}
					catch(invalid_argument &badarg)
					{//timestamp couldn't be parsed. assume someone is trying something fishy
						string user = postgres->userFromFd(sd, COMMAND, iterationKey);
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_BADCMD, originalBufferCmd, user, INBOUNDLOG, ip, iterationKey));

						string error =  "INVALID ARGUMENT EXCEPTION: (uint64_t)stoull (string too long) could not parse timestamp";
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

						string invalid = to_string(now) + "|resp|invalid|command\n";
						write2Client(invalid, sdssl, iterationKey);
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip, iterationKey));
					}
					catch(out_of_range &exrange)
					{
						string user = postgres->userFromFd(sd, COMMAND, iterationKey);
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_BADCMD, originalBufferCmd, user, INBOUNDLOG, ip, iterationKey));

						string error = "OUT OF RANGE (vector<string> parsed from command) EXCEPTION: client sent a misformed command";
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_BADCMD, error, user, ERRORLOG, ip, iterationKey));

						string invalid = to_string(now) + "|resp|invalid|command\n";
						write2Client(invalid, sdssl, iterationKey);
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_BADCMD, invalid, user, OUTBOUNDLOG, ip, iterationKey));
					}
					invalidcmd:; //bad timestamp, invalid sessionid, not real call... etc.
				}
				else if(sdstate == SOCKMEDIANEW)
				{//timestamp|sessionid (of the user this media fd should be registered/associated to)
					//workaround for jclient sending first byte of a command separately
					//after the initial login
					string bufferString(inputBuffer);

					//what was previously a workaround now has an official purpose: heartbeat/ping ignore byte
					if(bufferString == JBYTE)
					{
#ifdef VERBOSE
						cout << "Got a " << JBYTE << " cap for media sd " << sd << "\n";
#endif
						goto skipfd;
					}
					string ip = ipFromSd(sd);
					//need to write the string to the db before it gets mutilated by strtok in parse(bufferMedia)
					postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIANEW, to_string(inputBuffer), DONTKNOW, INBOUNDLOG, ip, iterationKey));
					vector<string> commandContents = parse(inputBuffer);

					try
					{
						uint64_t sessionid = (uint64_t)stoull(commandContents.at(1));
						string intendedUser = postgres->userFromSessionid(sessionid, iterationKey);

						//check timestamp is ok
						time_t now = time(NULL);
						uint64_t timestamp = (uint64_t)stoull(commandContents.at(0));
						uint64_t fivemins = 60*5;
						uint64_t timeDifference = (uint64_t)std::llabs(now - timestamp);
						if(timeDifference > fivemins)
						{
							uint64_t mins = timeDifference/60;
							uint64_t seconds = timeDifference - mins*60;
							string error = "timestamp " + to_string(mins) + ":" + to_string(seconds) + " outside 5min window of error";
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							goto skipreg;
						}

						//check sessionid belongs to a signed in user
						if(intendedUser == "")
						{
							string error = "user cannot be identified from session id";
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							goto skipreg;
						}
						string message = "According to the session id, the media socket is for: " + intendedUser;
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIANEW, message, intendedUser, INBOUNDLOG, ip, iterationKey));

						//get the user's command fd to do an ip lookup of which ip the command fd is associated with
						int cmdfd = postgres->userFd(intendedUser, COMMAND, iterationKey);
						if(cmdfd == 0)
						{//with a valid timestamp, valid sessionid, there is no cmd fd for this user??? how??? you must log in through a cmd fd to get a sessionid
							string error = "(possible bug) valid timestamp and sessionid but " + intendedUser + " has no command fd. can't continue association of media socket";
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							goto skipreg;
						}

						//besides presenting the right sessionid to associate with the user (which could be a lucky guess)
						//	try and match the ip address of the media and command. not a 100% guarantee still, but if this
						//	fails, that is at least another way to figure out something isn't right.	
						// https://stackoverflow.com/questions/20472072/c-socket-get-ip-adress-from-filedescriptor-returned-from-accept
						struct sockaddr_in thisfd;
						socklen_t thisfdSize = sizeof(struct sockaddr_in);
						getpeername(sd, (struct sockaddr*) &thisfd, &thisfdSize);
						int thisfdip = thisfd.sin_addr.s_addr;

						struct sockaddr_in cmdFdInfo;
						socklen_t cmdInfoSize = sizeof(struct sockaddr_in);
						getpeername(cmdfd, (struct sockaddr*) &cmdFdInfo, &cmdInfoSize);
						int cmdip = cmdFdInfo.sin_addr.s_addr;

						if(thisfdip != cmdip)
						{//valid timestamp, valid sessionid, sessionid has command fd... but the media port association came from a different ip than the command fd...??? HOW??? all requests come from a cell phone app with 1 ip...
							string error = "SOMETHING IS REALLY WRONG. with a valid timestamp, sessionid, and a command fd associated with the sessionid, the request to associate the media fd is coming from another ip???\n";
							error = error + " last registered from ip address:" + to_string(inet_ntoa(cmdFdInfo.sin_addr)) + "\n";
							error = error + " is CURRENTLY registering from ip address: " + to_string(inet_ntoa(thisfd.sin_addr));
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIANEW, error, intendedUser, ERRORLOG, ip, iterationKey));
							goto skipreg;
						}
						postgres->setFd(sessionid, sd, MEDIA, iterationKey);
						sdinfo[sd] = SOCKMEDIAIDLE;

					}
					catch(invalid_argument &badarg)
					{
						string error = "can't get timestamp when trying establish which client a media socket should go to";
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIANEW, error, DONTKNOW, ERRORLOG, ip, iterationKey));
					}
					catch(out_of_range &exrange)
					{
						string error = "client sent a misformed media port association request, out of range exception";
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIANEW, error, DONTKNOW, ERRORLOG, ip, iterationKey));
					}

					skipreg:; //skip media fd registration. something didn't check out ok.
				}
				else if(sdstate <= SOCKMEDIAIDLE)
				{
#ifdef VERBOSE
					if(sdstate == SOCKMEDIAIDLE)
					{
						cout << "received data on an established media socket. ignore it\n";
#ifdef JCALLDIAG
						cout << "Got : " << inputBuffer << "\n";
#endif
					}
					else //if(sdstate < -3)
					{
						cout << "received data on a media socket waiting for a call accept\n";
#ifdef JCALLDIAG
						cout << "Got : " << inputBuffer << "\n";
#endif
					}
#endif //VERBOSE

				}
				else if(sdstate > 0) //in call
				{
					//when in call your sdstate is the media socket descriptor of the person you're calling
					//not avoiding duplicate code of generating log stuff: ip, user, related key because
					//sending media will occur many times/sec. don't want to go through all the trouble of generating
					//logging related stuff if it's never going to be used most of the time.
#ifdef VERBOSE
#ifdef JCALLDIAG
					cout << "received " << bufferRead << " bytes of call data\n";
#endif
#endif
					if(clientssl.count(sdstate) > 0) //the other person's media sd does exist
					{
						if(FD_ISSET(sdstate, &writefds))
						{//only send if the socket's buffer has place
							SSL *recepient = clientssl[sdstate];
							SSL_write(recepient, inputBuffer, bufferRead);
						}
						else
						{//if there is no place, just drop the 32bytes of voice
						 //a backlog of voice will cause a call lag. better to ask again and say "didn't catch that"

							int fails = failCount[sdstate];
							string ip = ipFromSd(sdstate); //log the ip of the socket that can't be written to
							string user = postgres->userFromFd(sdstate, MEDIA, iterationKey); //log who couldn't be sent media
							string error = "couldn't write to media socket because it was not ready. failed " + to_string(fails) + " times";
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIACALL, error, user, ERRORLOG, ip, iterationKey));

							fails++;
							failCount[sdstate] = fails;
							if(fails > FAILMAX)
							{
								string error = "reached maximum media socket write failure of: " + to_string(FAILMAX);
								postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIACALL, error, user, ERRORLOG, ip, iterationKey));
								removeClient(sdstate, iterationKey);
								//on the next round if(clientssl.count(sdstate)) will fail and go to
								//the else which will send the call drop. waiting for the next round to
								//avoid copying and pasting identical code
							}
						}
					}
					else
					{
						//call drop logic: example of touma calling zapper and touma's connection dies
						//if touma's connetion dies during the current round of "select", zapper's kb of
						//media will just be lost in the above if block. it won't reach this else block yet
						//because touma will still have a media port
						//
						//if touma's connection died during a previous round of select, you cannot send
						//timestamp|call|end|touma to zapper because touma's file/socket descriptor records have
						//been removed form the database. at the present, the state of zapper'd media fd = touma media fd.
						//because the record has been removed, you can't do postgres->userFromFd(zapper_mediafd_state, MEDIA)
						//to find out she's in a call with touma. 
						//therefore you have to send a different command... the call drop command

						//logging related stuff
						string ip = ipFromSd(sd);

						//reset the media connection state
						string user = postgres->userFromFd(sd, MEDIA, iterationKey);
						sdinfo[sd] = SOCKMEDIAIDLE;

						//drop the call for the user
						time_t now = time(NULL);
						uint64_t sessionid = postgres->userSessionId(user, iterationKey);
						if(sessionid == 0)
						{
							string error = "call was dropped but the user had no session id?? possible bug";
							postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIACALL, error, user, ERRORLOG, ip, iterationKey));
							goto skipfd;
						}

						//write to the person who got dropped's command fd that the call was dropped
						string drop = to_string(now) + "|call|drop|" + to_string(sessionid);
						int commandfd = postgres->userFd(user, COMMAND, iterationKey);
						SSL *cmdSsl = clientssl[commandfd];
						write2Client(drop, cmdSsl, iterationKey);
						postgres->insertLog(DBLog(Utils::millisNow(), TAG_MEDIACALL, drop, user, OUTBOUNDLOG, ip, iterationKey));
					}
				}

			}// if FD_ISSET : figure out command or voice and handle appropriately
		skipfd:; //fd was dead. removed it. go on to the next one
		}// for loop going through the fd set

		//now that all fds are finished inspecting, remove any of them that are dead.
		//don't mess with the map contents while the iterator is live.
		//removing while runnning causes segfaults because if the removed item gets iterated over after removal
		//it's no longer there so you get a segfault
		if(removals.size() > 0)
		{
#ifdef VERBOSE
			cout << "Removing " << removals.size() << " dead/leftover sockets\n";
#endif
			vector<int>::iterator rmit;
			for(rmit = removals.begin(); rmit != removals.end(); ++rmit)
			{
				int kickout = *rmit;
				if(clientssl.count(kickout) > 0)
				{
					removeClient(kickout, initkey);
				}
			}
			removals.clear();
		}
#ifdef VERBOSE
		cout << "_____________________________________\n_________________________________\n";
#endif
	}

	//stop postgres
	PGUtils *instance = PGUtils::getInstance();
	instance->killInstance();

	//openssl stuff
	SSL_CTX_free(sslcontext);
	ERR_free_strings();
	EVP_cleanup();
	
	//close ports
	close(cmdFD);
	close(mediaFD);
	return 0; 
}

//use a vector to prevent reading out of bounds
vector<string> parse(char command[])
{
//timestamp|login|username|passwd
//timestamp|call|otheruser|sessionid
//timestamp|lookup|user|sessionid
//timestamp|reject|user|sessionid
//timestamp|accept|user|sessionid
//timestamp|timeout|user|sessionid
//timestamp|end|user|sessionid

//timestamp|sessionid : for registering media port
	char *token;
	int i = 0;
	vector<string> result;
	token = strtok(command, "|");
	while(token != NULL && i < 4)
	{
		result.push_back(string(token));
		token = strtok(NULL, "|");
		i++;
	}
#ifdef JAVA1BYTE
	try
	{
		string timestamp = result.at(0);
		size_t notjbyte = timestamp.find_first_not_of(JBYTE[0]);
		if(notjbyte != string::npos)
		{
			result.at(0) = timestamp.substr(notjbyte);
		}
	}
	catch (out_of_range &oorange)
	{
		//nothing you can really do if the vector result has nothing. just don't crap out
	}
#endif
	return result;
}

// sd: a client's socket descriptor
// to make things easier, this function will attempt to find both the media and cmd fd
//	for the user to be removed.
void removeClient(int sd, uint64_t relatedKey)
{
	PGUtils *postgres = PGUtils::getInstance();
	string uname = postgres->userFromFd(sd, COMMAND, relatedKey); //make a lucky guess you got the command fd
	int media, cmd;

#ifdef JSTOPMEDIA
	//make the assumption. if it's right remove both. if it's wrong then... it's still right. remove only the media
	cmd = sd;
	media = postgres->userFd(uname, MEDIA, relatedKey);
#else
	/*
	 * The actual correct method of removing both sockets regardless of what was supplied
	 */
	if(!uname.empty())
	{//lucky guess was right
		cmd = sd;
		media = postgres->userFd(uname, MEDIA, relatedKey);
	}
	else
	{//lucky guess was wrong. then you got the media fd
		uname = postgres->userFromFd(sd, MEDIA, relatedKey);
		cmd = postgres->userFd(uname, COMMAND, relatedKey);
		media = sd;
	}
#endif

#ifdef VERBOSE
	cout << "removing " << uname << "'s socket descriptors (cmd, media): (" << cmd << "," << media << ")\n";
#endif

	//if for weird reasons the user was just a media port with no cmd don't freak out and crash over no command fd
	if(cmd > 4) //0 stdin, 1 stdout, 2 stderr, 3 command receive, 4, media receive
	{
		if(sdinfo.count(cmd) > 0)
		{
			sdinfo.erase(cmd);
		}
		
		if(failCount.count(cmd > 0))
		{
			failCount.erase(cmd);
		}

		if(clientssl.count(cmd) > 0)
		{
			SSL_shutdown(clientssl[cmd]);
			SSL_free(clientssl[cmd]);
			shutdown(cmd, 2);
			close(cmd);
			clientssl.erase(cmd);
		}
	}

	//if the user never got around to registering a media port, then also don't freak out and crash
	if(media > 4)
	{
		if(sdinfo.count(media) > 0)
		{
			sdinfo.erase(media);
		}
		
		if(failCount.count(cmd > 0))
		{
			failCount.erase(cmd);
		}

		if(clientssl.count(media) > 0)
		{
			SSL_shutdown(clientssl[media]);
			SSL_free(clientssl[media]);
			shutdown(media, 2);
			close(media);
			clientssl.erase(media);
		}
	}

	//incase of crash, there will be no entires in the hash table and tree. skip these pairs and just flush out
	//	the irrelevant db info
	postgres->clearSession(uname, relatedKey);
}

//before doing an accept, reject, end command check to see if it's for a real call
//	or someone trying to get smart with the server
bool isRealCall(string persona, string personb, uint64_t relatedKey)
{
	PGUtils *postgres = PGUtils::getInstance();
	string prefix =  "call between " + persona + " && " + personb + ": ";

	//check if A and B even have media FDs
	int afd = postgres->userFd(persona, MEDIA, relatedKey);
	int bfd = postgres->userFd(personb, MEDIA, relatedKey);
	if(afd == 0)
	{
#ifdef VERBOSE
		cout << prefix << persona << " doesn't even have a media fd\n";
#endif
		return false;
	}
	if(bfd == 0)
	{
#ifdef VERBOSE
		cout << prefix << personb << " doesn't even have a media fd\n";
#endif
		return false;
	}

	int astatus = sdinfo[afd];
	if(!((astatus ==  -bfd) || (astatus == bfd)))
	{//apparently A isn't waiting for a call with B to start
#ifdef VERBOSE
		cout << prefix << persona << " isn't expecting a call from or in a call with " << personb;
#endif
		return false;
	}

	int bstatus = sdinfo[bfd];
	if(!((bstatus == -afd) || (bstatus == afd)))
	{//apparently B isn't waiting for a call with A to start
#ifdef VERBOSE
		cout << prefix << personb << " isn't expecting a call from or in a call with" << persona;
#endif
		return false;
	}

	//A and B both have a mediafds and are both mutually waiting for a call to start between them
#ifdef VERBOSE
	cout << prefix << "is a real call\n";
#endif
	return true;	
}


// write a message to a client
void write2Client(string response, SSL *respSsl, uint64_t relatedKey)
{
	int errValue = SSL_write(respSsl, response.c_str(), response.size());
	if(errValue <= 0)
	{
		PGUtils *postgres = PGUtils::getInstance();
		int socket = SSL_get_fd(respSsl);
		string user = postgres->userFromFd(socket, COMMAND, relatedKey);
		string error = "ssl_write returned an error of: " + to_string(errValue) + " while trying to write to the COMMAND socket";
		postgres->insertLog(DBLog(Utils::millisNow(), TAG_SSLCMD, error, ERRORLOG, relatedKey));
	}
}

//https://stackoverflow.com/questions/1798112/removing-leading-and-trailing-spaces-from-a-string
string trim (string str)
{//
	//nothing to trim in a blank string
	if(str.length() == 0)
	{
		return str;
	}

	size_t beginning = str.find_first_not_of(" \r\n\t");

	//if there is a comment then start looking BEFORE the comment otherwise find_last_not_of
	//will "OK" the comment characters and fail to trim
	size_t comment = str.find('#');
	size_t ending;
	if(comment != string::npos)
	{
		ending = str.find_last_not_of(" #\r\n\t", comment); //strip off the comment
	}
	else
	{
		ending = str.find_last_not_of(" #\r\n\t"); //strip off the comment
	}
	size_t range = ending-beginning+1;
	return str.substr(beginning, range);
}

string ipFromSd(int sd)
{
	struct sockaddr_in thisfd;
	socklen_t thisfdSize = sizeof(struct sockaddr_in);
	getpeername(sd, (struct sockaddr*) &thisfd, &thisfdSize);
	return to_string(inet_ntoa(thisfd.sin_addr));
}
