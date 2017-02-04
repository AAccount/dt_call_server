#include <string>
#include <vector>
#include <openssl/ssl.h>

using namespace std;

//parse incoming server commands (split the incoming command string by the | character)
vector<string> parse(char command[]);

//remove a client's command and media or only media depending what kind of sd is given
void removeClient(int sd, uint64_t relatedKey);

//verify the call is real and not a malicious hand crafted command
bool isRealCall(string persona, string personb, uint64_t relatedKey);

//convert the string to c char[] and send it by ssl* (when sending, send only as many bytes as there are characters
// and not the whole command string buffer [] size
void write2Client(string response, SSL *respSsl, uint64_t relatedKey);

//used for parsing the configuration file: remove whitespace preceding/trailing and comments
string trim (string str);

//get the ip address of a socket descriptor in human readable 192.168.1.1 format
string ipFromSd(int sd);
