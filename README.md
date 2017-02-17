# dt_call_server
VoIP server for android and test java client

The VoIP server for my android and test java client. Admitedly the weakest link of the whole VoIP Project.
Based on a heavily beefed up school assignment dealing with the select system call.

Commands are generally sent in the following fomrat: time stamp | command | (arg1) | session id OR (arg 2)

Commands are parsed by the "|" character.

Each user has 2 sockets: a command socket (to send commands on) and media socket (to send/receive voice data).

Timestamp is to help guard against replay. The window for acceptable timestamps os configurable.

All constants are stored in const.h
When a socket is created it is assigned a state: 
* command: a command socket to receive and parse commands.
* media new: a new media socket that has not been associated with a user yet.
* media idle: a media socket that has been associated with a user but isn't doing anything.
* (another user's media socket fd#): media socket is used in a call. Send voice data to this person's media socket.

There is a special "jbyte" which when sent to a socket is ignored. 

Its purpose is for the client to periodically ping the server to keep the nat pathways open.

Sockets are all on a read timeout to prevent a bad connection stalling the whole server.


Configurations for this server are stored in a standard unix style conf file with "#" as the comment delimiter.

A sample is provided with full explanations.

Comments can be inline or on their own line.

If you have any ideas of how to make this better please do say so. This is the component that could stand for the most improvement.

I'm just going with what I learned in class. The C/C++ hybrid is just what I picked up teaching myself.

All test accounts are based on characters from: https://myanimelist.net/anime/4654/Toaru_Majutsu_no_Index

(Watch it and its spinoff. They're really good.)
