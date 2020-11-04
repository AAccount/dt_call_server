#include "CommandContext.hpp"

CommandContext::CommandContext(Logger* clogger, UserUtils* cuserUtils, int cfd, Client* cclient, std::unordered_map<int, std::unique_ptr<Client>>& cclientMap, const std::string& cogBuffer, const std::vector<std::string>& ccommandContents, const std::string& cuser, std::vector<int>& cremovals):
logger(clogger),
userUtils(cuserUtils),
fd(cfd),
client(cclient),
clientMap(cclientMap),
originalBufferString(cogBuffer),
commandContents(ccommandContents),
user(cuser),
removals(cremovals)
{
}

CommandContext::~CommandContext(){}

Logger* CommandContext::getLogger() const
{
	return logger;
}

UserUtils* CommandContext::getUserUtils() const
{
	return userUtils;
}

int CommandContext::getFd() const
{
	return fd;
}

Client* CommandContext::getClient() const
{
	return client;
}

std::unordered_map<int, std::unique_ptr<Client>>& CommandContext::getClientMap() const
{
	return clientMap;
}

std::string CommandContext::getOriginalBufferString() const
{
	return originalBufferString;
}

const std::vector<std::string> CommandContext::getCommandContents() const
{
	return commandContents;
}

const std::string CommandContext::getUser() const
{
	return user;
}

std::vector<int>& CommandContext::getRemovals() const
{
	return removals;
}