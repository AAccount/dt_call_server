/*
 * CommandContext.hpp
 *
 *  Created on: Oct 26, 2020
 *      Author: Daniel
 */

#ifndef COMMAND_CONTEXT_
#define COMMAND_CONTEXT_

#include <string>
#include <vector>

#include "../User/Client.hpp"
#include "../User/UserUtils.hpp"
#include "../Log/Logger.hpp"

class CommandContext
{
	public:
		CommandContext(Logger* clogger, UserUtils* cuserUtils, int cfd, Client* cclient, std::unordered_map<int, std::unique_ptr<Client>>& cclientMap, const std::string& cogBuffer, const std::vector<std::string>& ccommandContents, const std::string& cuser, std::vector<int>& cremovals);
		virtual ~CommandContext();

		Logger* getLogger() const;
		UserUtils* getUserUtils() const;

		int getFd() const;
		Client* getClient() const;
		std::unordered_map<int, std::unique_ptr<Client>>& getClientMap() const;
		std::string getOriginalBufferString() const;
		const std::vector<std::string> getCommandContents() const;
		const std::string getUser() const;
		std::vector<int>& getRemovals() const;

	private:
		Logger* logger;
		UserUtils* userUtils;
	
		int fd;
		Client* client;
		std::unordered_map<int, std::unique_ptr<Client>>& clientMap;

		std::string originalBufferString;
		const std::vector<std::string> commandContents;
		const std::string user;

		std::vector<int>& removals;
};

#endif