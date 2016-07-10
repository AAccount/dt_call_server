#define MAXCMD 100 //how many characters a command with params can be 
#define MAXMEDIA 1024 //how much media is transferred between users at a time
					//media buffer must be larger than media frame (amr in this case) or it won't work
					//example: amr encodes 32 bytes, making the buffer 64 bytes
#define MAXLISTENWAIT 5

//which fd to set
#define COMMAND 1
#define MEDIA 2

//errors
#define EGENERIC -1 //internal error. something went wrong that shouldn't
#define ENOUSER -2 //no user matches the parameters provided
#define EPASS -3 //bad password
#define ENOFD -4 //no file/socket descriptor found for the parameters provided
#define EPARAM -5 //non sense parameter supplied

//socket state
// state > 0 : incall with that descriptor
#define SOCKCMD -1
#define SOCKMEDIANEW -2
#define SOCKMEDIAIDLE -3

//call related stuff
#define INITWAITING 100

//java 1 byte ignored character
#define JBYTE "D"

//timeouts
#define ALARMTIMEOUT 3 //seconds
#define SOCKETTIMEOUT 2 //seconds
#define WSELECTTIMEOUT 100000 //microseconds

//maximum amount of times a socket can write fail before killing
#define FAILMAX 10

//where the configuration file is
#define CONFFILE "/home/Daniel/dtoperator"
