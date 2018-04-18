#ifndef SERVER_HPP_
#define SERVER_HPP_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cmath>
#include <string>
#include <unordered_map> //hash table
#include <vector>
#include <fstream>
#include <random>
#include <algorithm>
#include <memory>

#include "Log.hpp"
#include "UserUtils.hpp"
#include "const.h"
#include "Utils.hpp"
#include "server_init.hpp"
#include "Logger.hpp"
#include "sodium_utils.hpp"

struct UdpArgs
{
	int port;
	unsigned char sodiumPublicKey[crypto_box_PUBLICKEYBYTES];
	unsigned char sodiumPrivateKey[crypto_box_SECRETKEYBYTES];
};

//dedicated function for handling a call. each call is processed on its own thread.
void* udpThread(void *ptr);

//parse incoming server commands (split the incoming command string by the | character)
std::vector<std::string> parse(unsigned char command[]);

//remove a client's command and media or only media depending what kind of sd is given
void removeClient(int sd);

//verify the call is real and not a malicious hand crafted command
//persona is the one who will be sent an invalid command if it is not real.
bool isRealCall(std::string persona, std::string personb, Log::TAG tag);

//convert the string to c char[] and send it by ssl* (when sending, send only as many bytes as there are characters
// and not the whole command string buffer [] size
void write2Client(std::string response, SSL *respSsl);

//get the ip address of a socket descriptor in human readable 192.168.1.1 format
std::string ipFromFd(int sd);

//accept ssl commands from the command socket
void sslAccept(int cmdFD, SSL_CTX* sslcontext, struct timeval* unauthTimeout);

//read an SSL socket into param inputBuffer. maximum read size in const.h
int readSSL(SSL *sdssl, unsigned char inputBuffer[]);

//check the timestamp string to see if it's within the limits
bool checkTimestamp(const std::string& tsString, Log::TAG tag, const std::string& errorMessage, const std::string& user, const std::string& ip);

//check to see if the bytes in the buffer are legitimate ascii characters of interest and doesn't contain any junk
bool legitimateAscii(unsigned char* buffer, int length);

#endif
