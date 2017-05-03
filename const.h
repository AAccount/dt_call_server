#define BUFFERSIZE 1024 //how much media is transferred between users at a time
					//media buffer must be larger than media frame (amr in this case) or it won't work
					//example: amr encodes 32 bytes, making the buffer 64 bytes
#define MAXLISTENWAIT 5
#define MARGIN_OF_ERROR 5 //+- amount the command timestamp can be off by in minutes

//which fd to set
#define COMMAND 1
#define MEDIA 2

//socket state
// state > 0 : incall with that descriptor
#define SOCKCMD -1
#define SOCKMEDIANEW -2
#define SOCKMEDIAIDLE -3

//java 1 byte ignored character
#define JBYTE "D"

//timeouts
#define READTIMEOUT 500000 //microseconds
#define WSELECTTIMEOUT 100 //microseconds

//maximum amount of times a socket can write fail before killing
#define FAILMAX 10

//where the configuration file is
//#define CONFFILE "/etc/dtoperator/dtoperator.conf"
//#define USERSFILE "/etc/dtoperator/users"
//#define LOGFOLDER "/var/log/dtoperator/"
#define CONFFILE "/home/Daniel/dtoperator/dtoperator.conf"
#define USERSFILE "/home/Daniel/dtoperator/users"
#define LOGFOLDER "/tmp/"

#define LOGPREFIX "log "

#define DEFAULTCMD 1991
#define DEFAULTMEDIA 2014
#define DEFAULTCIPHERS "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA"
