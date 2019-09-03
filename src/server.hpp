#ifndef SERVER_HPP_
#define SERVER_HPP_

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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <arpa/inet.h>

#include <cmath>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <random>
#include <algorithm>
#include <memory>
#include <thread>

#include "Log.hpp"
#include "UserUtils.hpp"
#include "const.h"
#include "ServerUtils.hpp"
#include "server_init.hpp"
#include "Logger.hpp"
#include "sodium_utils.hpp"
#include "Client.hpp"
#include "stringify.hpp"

//send a call end command. its own function (unlike the other commands) to detect dropped calls
void sendCallEnd(std::string user);

//dedicated function for handling a call. each call is processed on this thread.
void udpThread(int port, std::unique_ptr<unsigned char[]> publicKey, std::unique_ptr<unsigned char[]> privateKey);

//parse incoming server commands (split the incoming command string by the | character)
std::vector<std::string> parse(unsigned char command[]);

//remove a client's command and media or only media depending what kind of sd is given
void removeClient(int sd);

//verify the call is real and not a malicious hand crafted command
//persona is the one who will be sent an invalid command if it is not real.
bool isRealCall(const std::string& persona, const std::string& personb, Log::TAG tag);

//convert the string to c char[] and send it by ssl* (when sending, send only as many bytes as there are characters
// and not the whole command string buffer [] size
void write2Client(const std::string&, int sd);

//get the ip address of a socket descriptor in human readable 192.168.1.1 format
std::string ipFromFd(int sd);

//accept ssl commands from the command socket
void socketAccept(int cmdFD, struct timeval* unauthTimeout);

//check the timestamp string to see if it's within the limits
bool checkTimestamp(const std::string& tsString, Log::TAG tag, const std::string& errorMessage, const std::string& user, const std::string& ip);

//check to see if the bytes in the buffer are legitimate ascii characters of interest and doesn't contain any junk
bool legitimateAscii(unsigned char* buffer, int length);

#endif
