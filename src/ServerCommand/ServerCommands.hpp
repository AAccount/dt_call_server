/*
 * User.cpp
 *
 *  Created on: Oct 26, 2020
 *      Author: Daniel
 */
#ifndef CONST_SERVER_COMMAND
#define CONST_SERVER_COMMAND

#include <string>
#include <memory>

#include "sodium.h"
#include "unistd.h"

#include "../sodium_utils.hpp"
#include "../Log/Log.hpp"
#include "CommandContext.hpp"
#include "CommandUtils.hpp"

namespace ServerCommand
{
	bool decrypt(CommandContext& ctx, const std::unique_ptr<unsigned char[]>& inputBuffer, int length, const std::unique_ptr<unsigned char[]>& symmetricKey, std::string& ogCommand, std::vector<std::string>& commandContents);
	void initClient(CommandContext& ctx, const std::unique_ptr<unsigned char[]>& inputBufferArray, int amountRead, const std::unique_ptr<unsigned char[]>& sodiumPublicKey, const std::unique_ptr<unsigned char[]>& sodiumPrivateKey);
	void login1(CommandContext& ctx, const std::unique_ptr<unsigned char[]>& sodiumPrivateKey);
	void login2(CommandContext& ctx);
	void call(CommandContext& ctx);
	void accept(CommandContext& ctx);
	void passthrough(CommandContext& ctx);
	void ready(CommandContext& ctx);
	void end(CommandContext& ctx);

	bool isRealCall(CommandContext& ctx, const std::string& persona, const std::string& personb, Log::TAG tag);
	void write2Client(CommandContext& ctx, const std::string& response, int sd);
	std::string ipFromFd(int sd);
	void sendCallEnd(CommandContext& ctx, const std::string& user);
};
#endif