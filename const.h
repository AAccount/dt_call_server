#ifndef CONST_INCLUDE
#define CONST_INCLUDE

#define VERSION "4.1:{git revision here}"

#define COMMANDSIZE 2048
#define MEDIASIZE 1200
#define MAXLISTENWAIT 5
#define MARGIN_OF_ERROR 5 //+- amount the command timestamp can be off by in minutes
#define CHALLENGE_LENGTH 200
#define SESSION_KEY_LENGTH 59
#define SESSION_KEY_PLACEHOLDER "SESSION_KEY_HERE"
#define AES_PLACEHOLDER "ENCRYPTED_AES_KEY_HERE"
#define DT_SSL_ACCEPT_RETRIES 10 //prefix my initials to make it NOT look like an official openssl SSL_... constant
#define COMMAND_MAX_SEGMENTS 5 //to prevent the command parser from going on and on from a malicious command

//java 1 byte ignored character
#define JBYTE "D"

//timeouts
#define UNAUTHTIMEOUT 500000 //microseconds
#define AUTHTIMEOUT 2 //seconds

//where the configuration file is
//#define LIVE
#ifdef LIVE
	#define CONFFILE "/etc/dtoperator/dtoperator.conf"
	#define USERSFILE "/etc/dtoperator/users"
	#define LOGFOLDER "/var/log/dtoperator/"
#else
	#define CONFFILE "/home/Daniel/dtoperator/dtoperator.conf"
	#define USERSFILE "/home/Daniel/dtoperator/users"
	#define LOGFOLDER "/tmp/"
#endif

#define LOGPREFIX "log "

#define DEFAULTCMD 1991
#define DEFAULTMEDIA 1961
#define DEFAULTCIPHERS "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA"

typedef enum {NONE, INIT, INCALL, INVALID} ustate; //user state
#endif
