#ifndef SERVER_HPP_
#define SERVER_HPP_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <cmath>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <random>
#include <algorithm>
#include <memory>
#include <thread>
#include <functional>

#include "Log/Log.hpp"
#include "Log/Logger.hpp"
#include "User/UserUtils.hpp"
#include "User/Client.hpp"
#include "ServerCommand/ServerCommands.hpp"
#include "ServerCommand/CommandContext.hpp"
#include "ServerCommand/CommandUtils.hpp"
#include "ServerCommand/UdpContext.hpp"
#include "ServerCommand/UdpCommand.hpp"
#include "const.h"
#include "ServerUtils.hpp"
#include "server_init.hpp"
#include "sodium_utils.hpp"
#include "stringify.hpp"

//send a call end command. its own function (unlike the other commands) to detect dropped calls
void sendCallEnd(const std::string& user);

//dedicated function for handling a call. each call is processed on this thread.
void udpThread(int port, const std::unique_ptr<unsigned char[]>& publicKey, const std::unique_ptr<unsigned char[]>& privateKey, std::unordered_map<int, std::unique_ptr<Client>>& clients);

//remove a client's command and media or only media depending what kind of sd is given
void removeClient(int sd, std::unordered_map<int, std::unique_ptr<Client>>& clients);

//accept ssl commands from the command socket
void socketAccept(int cmdFD, std::unordered_map<int, std::unique_ptr<Client>>& clients);

#endif
