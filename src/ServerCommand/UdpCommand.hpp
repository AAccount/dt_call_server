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
#include "../ServerUtils.hpp"

namespace UdpCommand
{
	bool decrypt(UdpContext& ctx, const std::unique_ptr<unsigned char[]>& mediaBuffer, int receivedLength);
	void registerUser(UdpContext& ctx, std::unordered_map<int, std::unique_ptr<Client>>& clientMap);
	void ack(UdpContext& ctx, std::unordered_map<int, std::unique_ptr<Client>>& clientMap);
	void call(UdpContext& ctx, const std::unique_ptr<unsigned char[]> &mediaBuffer, int receivedLength);
};
#endif