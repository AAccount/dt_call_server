# VoIP server for [AClient](https://github.com/AAccount/dt_call_aclient) and [GTK Client](https://github.com/AAccount/dt_call_gtkclient)

The VoIP server for my android and desktop Linux GTK client. Its dependancy is libsodium.

Works on Linux:
![Linux Screenshot](https://github.com/AAccount/dt_call_server/blob/master/screenshots/Screenshot%20Fedora24.png "Call server running on Fedora 24 x64")
and FreeBSD:
![FreeBSD Screenshot](https://github.com/AAccount/dt_call_server/blob/master/screenshots/Screenshot%20FreeBSD11.png "Call server running on FreeBSD 11 amd64")

The server is written in C/(self taught)C++ to minimize resource usage. Coordinating 1 voice call on my former 2004 Pentium4 Northwood with 2GB of ram home server running Debian 8 x86 produces an occasional cpu spike of 0.5%.
![CPU Usage 2004era P4](https://github.com/AAccount/dt_call_server/blob/master/screenshots/Screenshot%20Live%20Call%20CPU.png)

Commands are sent as a string of characters delimited by the "|" character.

Each user has 2 sockets: a TCP command socket (to send commands on) and an ondemand UDP media socket (to send/receive voice data). 

UDP for voice is required for very crowded wifi networks where tcp's perfectionist attitude will cause it to severly delay voice packets and possibly close the connection for only a handful of unreceived packets. In VoIP (like high school English), quantity is more important than quality.

All commands are timestamped to help protect against replay. The window for acceptable timestamps is configurable.

All constants are stored in const.h

There is a special "jbyte" which is ignored when sent to the TCP command socket 
Its purpose is for the client to periodically ping the server to keep the nat pathways open. 
This VoIP system was designed to allow clients to connect from anywhere. 
Clients need not have a publicly accessible IP address.
As long as a bidirectional socket can be established from the client to the server it will work.

Sockets are all on a read timeout to prevent a bad connection stalling the whole server.

Configurations for this server are stored in a standard unix style conf files with "#" as the comment delimiter.
Comments can be inline or on their own line.

Server logs are stored in standard unix style plain text files that are automatically rotated every 24 hours.

All test accounts are based on characters from: https://myanimelist.net/anime/4654/Toaru_Majutsu_no_Index
(Watch it and its spinoff. They're really good.)
