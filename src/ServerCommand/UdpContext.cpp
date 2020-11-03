#include "UdpCommand.hpp"

UdpContext::UdpContext(Logger* clogger, UserUtils* cuserUtils, const std::unique_ptr<unsigned char[]>& cpublic, const std::unique_ptr<unsigned char[]>& cprivate, struct sockaddr_in& csender, int csenderLength, int cmediaFd, std::string& cuser):
logger(clogger),
userUtils(cuserUtils),
publicKey(cpublic),
privateKey(cprivate),
sender(csender),
senderLength(csenderLength),
mediaFd(cmediaFd),
user(cuser),
registrationString(""),
registrationContents()
{}

UdpContext::UdpContext(Logger* clogger, UserUtils* cuserUtils, const std::unique_ptr<unsigned char[]>& cpublic, const std::unique_ptr<unsigned char[]>& cprivate, struct sockaddr_in& csender, int csenderLength, int cmediaFd, std::string& cuser, std::string& cregistrationString, std::vector<std::string>& cregistrationContents):
logger(clogger),
userUtils(cuserUtils),
publicKey(cpublic),
privateKey(cprivate),
sender(csender),
senderLength(csenderLength),
mediaFd(cmediaFd),
user(cuser),
registrationString(cregistrationString),
registrationContents(cregistrationContents)
{}

UdpContext::~UdpContext()
{}

Logger* UdpContext::getLogger()
{
	return logger;
}

UserUtils* UdpContext::getUserUtils()
{
	return userUtils;
}

const std::unique_ptr<unsigned char[]>& UdpContext::getPublicKey()
{
	return publicKey;
}

const std::unique_ptr<unsigned char[]>& UdpContext::getPrivateKey()
{
	return privateKey;
}

const struct sockaddr_in& UdpContext::getSender()
{
	return sender;
}

int UdpContext::getSenderLength()
{
	return senderLength;
}

int UdpContext::getMediaFd()
{
	return mediaFd;
}

std::string UdpContext::getUser()
{
	return user;
}

std::string UdpContext::getRegistrationString()
{
	return registrationString;
}

std::vector<std::string> UdpContext::getRegistrationContents()
{
	return registrationContents;
}

void UdpContext::setUser(std::string user)
{
	this->user = user;
}

void UdpContext::setRegistrationString(std::string& reg)
{
	this->registrationString = reg;
}

void UdpContext::setRegistrationContents(std::vector<std::string>& contents)
{
	this->registrationContents = contents;
}