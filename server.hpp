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

#include "Log.hpp"
#include "UserUtils.hpp"
#include "const.h"
#include "Utils.hpp"
#include "server_init.hpp"

//dedicated function for handling a call. each call is processed on its own thread.
void* udpThread(void *ptr);

//parse incoming server commands (split the incoming command string by the | character)
std::vector<std::string> parse(char command[]);

//remove a client's command and media or only media depending what kind of sd is given
void removeClient(int sd);

//verify the call is real and not a malicious hand crafted command
//persona is the one who will be sent an invalid command if it is not real.
bool isRealCall(std::string persona, std::string personb, std::string tag, uint64_t iterationKey);

//convert the string to c char[] and send it by ssl* (when sending, send only as many bytes as there are characters
// and not the whole command string buffer [] size
void write2Client(std::string response, SSL *respSsl, uint64_t relatedKey);

//get the ip address of a socket descriptor in human readable 192.168.1.1 format
std::string ipFromFd(int sd);

//turn unsigned char array into string of #s
std::string stringify(unsigned char *bytes, int length);

//read an SSL socket into param inputBuffer. maximum read size in const.h
int readSSL(SSL *sdssl, char inputBuffer[], uint64_t iterationKey);

//send a call end/drop to this person
void sendCallEnd(std::string who, uint64_t iterationKey);

#endif
