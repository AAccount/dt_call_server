/*
 * User.cpp
 *
 *  Created on: Oct 30, 2020
 *      Author: Daniel
 */
#ifndef UDP_COMMAND_
#define UDP_COMMAND_

#include "CommandUtils.hpp"
#include "UdpContext.hpp"
#include "../User/Client.hpp"

bool udpDecrypt(UdpContext& ctx, std::unique_ptr<unsigned char[]>& mediaBuffer, int receivedLength);
void udpRegister(UdpContext& ctx, std::unordered_map<int, std::unique_ptr<Client>>& clientMap);
void udpAck(UdpContext& ctx, std::unordered_map<int, std::unique_ptr<Client>>& clientMap);
void udpCall(UdpContext& ctx, std::unique_ptr<unsigned char[]> &mediaBuffer, int receivedLength);

#endif