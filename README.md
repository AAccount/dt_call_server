# dt_call_server
VoIP server for android and test java client. Makes **encrypted** calls.

The VoIP server for my android and test java client.
Its only dependancies are libscrypt for password hashing and openssl for encrypting data.

The server works on Linux and FreeBSD.
![Linux Screenshot](https://github.com/AAccount/dt_call_server/blob/master/Screenshot%20Fedora24.png "Call server running on Fedora 24 x64")
![FreeBSD Screenshot](https://github.com/AAccount/dt_call_server/blob/master/Screenshot%20FreeBSD11.png "Call server running on FreeBSD 11 amd64")

Commands are generally sent in the following fomrat: time stamp | command | (arg1) | session id OR (arg 2)
Commands are parsed by the "|" character.

Each user has 2 sockets: a command socket (to send commands on) and media socket (to send/receive voice data).
Timestamp is to help guard against replay. The window for acceptable timestamps is configurable.

All constants are stored in const.h

When a socket is created it is assigned a state: 
* command: a command socket to receive and parse commands.
* media new: a new media socket that has not been associated with a user yet.
* media idle: a media socket that has been associated with a user but isn't doing anything.
* (another user's media socket fd#): media socket is used in a call. Send voice data to this person's media socket.

A dedicated thread handles live voice calls so processing and parsing commands will not disturb calls.

There is a special "jbyte", which when sent to a socket is ignored. 
Its purpose is for the client to periodically ping the server to keep the nat pathways open. 
This VoIP system was designed to allow clients to connect from anywhere. 
Clients need not have a publicly accessible IP address.
As long as a bidirectional socket can be established from the client to the server it will work.
(Even if the client is behind NAT or other middleware.)

Sockets are all on a read timeout to prevent a bad connection stalling the whole server.

Configurations for this server are stored in a standard unix style conf file with "#" as the comment delimiter.
Comments can be inline or on their own line.
User accounts are also stored in the same standard unix style conf.
A sample of each is provided with full explanations.


Server logs are stored in standard unix style plain text files that are automatically rotated every 24 hours.
If you have any ideas of how to make this better please do say so. 

I'm just going with what I learned in class. The C/C++ hybrid is just what I picked up teaching myself.

All test accounts are based on characters from: https://myanimelist.net/anime/4654/Toaru_Majutsu_no_Index
(Watch it and its spinoff. They're really good.)


Footnote: the design of this server makes it fully possible to do a MitM decryption of calls from the server. 
It is not designed for end to end encryption but rather client to server encrytption.
It is assumed you trust the person running the server.
