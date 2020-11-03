#ifndef CONST_INCLUDE
#define CONST_INCLUDE

#include <string>

inline const std::string VERSION = "7.7: {git revision here}";

const int COMMANDSIZE = 2048;
const int MEDIASIZE = 1200;
const int MAXLISTENWAIT = 5;
const int MARGIN_OF_ERROR = 5; //+- amount the command timestamp can be off by in minutes
const int CHALLENGE_LENGTH = 200;
const int SESSION_KEY_LENGTH = 59;
inline const std::string SESSION_KEY_PLACEHOLDER = "SESSION_KEY_HERE";
inline const std::string AES_PLACEHOLDER = "ENCRYPTED_AES_KEY_HERE";
const int COMMAND_MAX_SEGMENTS = 5; //passthrough
const int COMMAND_MIN_SEGMENTS = 3; //login1
const int REGISTRATION_SEGMENTS = 2;


//java 1 byte ignored character
inline const std::string JBYTE = "D";

//timeouts
const int UNAUTHTIMEOUT = 500000; //microseconds
const int AUTHTIMEOUT = 2; //seconds

const int DEFAULTCMD = 1991;
const int DEFAULTMEDIA = 1961;

typedef enum {NONE, INIT, INCALL, INVALID} ustate; //user state

#endif
