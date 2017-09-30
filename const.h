#ifndef CONST_INCLUDE
#define CONST_INCLUDE

#include <string>

const std::string& VERSION();

const int COMMANDSIZE = 2048;
const int MEDIASIZE = 1200;
const int MAXLISTENWAIT = 5;
const int MARGIN_OF_ERROR = 5; //+- amount the command timestamp can be off by in minutes
const int CHALLENGE_LENGTH = 200;
const int SESSION_KEY_LENGTH = 59;
const std::string& SESSION_KEY_PLACEHOLDER();
const std::string& AES_PLACEHOLDER();
const int DT_SSL_ACCEPT_RETRIES = 10; //prefix my initials to make it NOT look like an official openssl SSL_... constant
const int COMMAND_MAX_SEGMENTS = 5; //to prevent the command parser from going on and on from a malicious command

//java 1 byte ignored character
const std::string& JBYTE();

//timeouts
const int UNAUTHTIMEOUT = 500000; //microseconds
const int AUTHTIMEOUT = 2; //seconds

//where the configuration file is
//#define LIVE
const std::string& CONFFILE();
const std::string& USERSFILE();
const std::string& LOGFOLDER();

const std::string& LOGPREFIX();

const int DEFAULTCMD = 1991;
const int DEFAULTMEDIA = 1961;
const std::string& DEFAULTCIPHERS();

typedef enum {NONE, INIT, INCALL, INVALID} ustate; //user state

#endif
