#include <string>
#include <vector>
#include <openssl/ssl.h>

using namespace std;

vector<string> parse(char command[]); //parse incoming server commands
void removeClient(int sd); //remove a client's command and media or only media depending what kind of sd is given
bool isRealCall(string persona, string personb); //verify the call is real and not a malicious hand crafted command
void write2Client(string response, SSL *respSsl);
void alarm_handler(int signum);
string trim (string str);
string ipFromSd(int sd);
