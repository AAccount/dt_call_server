#include <string>
#include <vector>
#include <openssl/ssl.h>

#include "UserUtils.hpp"

using namespace std;

//a separate function to run on its own thread for handling live calls.
//	don't want and delay caused by processing commands, new logins to effect current calls
void* callThreadFx(void *unused);

//turn an incoming socket into a client ssl socket and prepare it for use
void setupSslClient(int fd, int fdType, struct sockaddr_in *info, socklen_t clilen, struct timeval *timeout, SSL_CTX *sslcontext, UserUtils *userUtils, uint64_t relatedKey);

//read data from an ssl socket and return the amount read
int readSSLSocket(SSL *sdssl, char *buffer, uint64_t iterationKey); //size is the standard buffer size in const.h

//parse incoming server commands (split the incoming command string by the | character)
vector<string> parse(char command[]);

//remove a client's command and media or only media depending what kind of sd is given
void removeClient(int sd);

//verify the call is real and not a malicious hand crafted command
bool isRealCall(string persona, string personb);

//convert the string to c char[] and send it by ssl* (when sending, send only as many bytes as there are characters
// and not the whole command string buffer [] size
void write2Client(string response, SSL *respSsl, uint64_t relatedKey);

//get the ip address of a socket descriptor in human readable 192.168.1.1 format
string ipFromSd(int sd);
