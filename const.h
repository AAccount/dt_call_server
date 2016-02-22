#define MAXCMD 100 //how many characters a command with params can be 
#define MAXMEDIA 4096 //how much media is transferred between users at a time

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
