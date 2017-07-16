# dt_call_server
VoIP server for android and test java client. Makes **end to end encrypted** calls.

The VoIP server for my android and test java client.
Its only dependancies is openssl for encrypting data and **public key authentication**.
This will not accept passwords for authentication.

The server works on Linux and FreeBSD.
![Linux Screenshot](https://github.com/AAccount/dt_call_server/blob/master/Screenshot%20Fedora24.png "Call server running on Fedora 24 x64")
![FreeBSD Screenshot](https://github.com/AAccount/dt_call_server/blob/master/Screenshot%20FreeBSD11.png "Call server running on FreeBSD 11 amd64")

The server is written in C/(self taught)C++ hybrid to minimize resource usage. Coordinating 1 voice call on my 2004 Pentium4 Northwood with 2GB of ram home server running Debian 8 x86 produces an occasional cpu spike of 0.5%.
![CPU Usage 2004era P4](https://github.com/AAccount/dt_call_server/blob/master/Screenshot%20Live%20Call%20CPU.png)

Commands are generally sent as a string of characters delimited by the "|" character.

Each user has 2 sockets: a TCP command socket (to send commands on) and an ondemand UDP media socket (to send/receive voice data). 

UDP for voice is required for very crowded wifi networks where tcp's perfectionist attitude will cause it to severly delay voice packets and possibly close the connection for only a handful of unreceived packets. In VoIP (like high school English), quantity is more important than quality.

Timestamps are to help guard against replay. The window for acceptable timestamps is configurable.

All constants are stored in const.h

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


All test accounts are based on characters from: https://myanimelist.net/anime/4654/Toaru_Majutsu_no_Index
(Watch it and its spinoff. They're really good.)


Footnote: MitM attack is no longer possible as of V4.0. Single use AES keys are RSA encrypted from client to client so not even the server will know what is being said. Any RSA key relay commands have the encrypted RSA censored out from the logs too.
