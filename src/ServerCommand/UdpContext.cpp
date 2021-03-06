#include "UdpCommand.hpp"

UdpContext::UdpContext(Logger* clogger, UserUtils* cuserUtils, const std::unique_ptr<unsigned char[]>& cpublic, const std::unique_ptr<unsigned char[]>& cprivate, const struct sockaddr_in& csender, int csenderLength, int cmediaFd, std::string& cuser):
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

UdpContext::UdpContext(Logger* clogger, UserUtils* cuserUtils, const std::unique_ptr<unsigned char[]>& cpublic, const std::unique_ptr<unsigned char[]>& cprivate, const struct sockaddr_in& csender, int csenderLength, int cmediaFd, std::string& cuser, std::string& cregistrationString, std::vector<std::string>& cregistrationContents):
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

Logger* UdpContext::getLogger() const
{
	return logger;
}

UserUtils* UdpContext::getUserUtils() const
{
	return userUtils;
}

const std::unique_ptr<unsigned char[]>& UdpContext::getPublicKey() const
{
	return publicKey;
}

const std::unique_ptr<unsigned char[]>& UdpContext::getPrivateKey() const
{
	return privateKey;
}

const struct sockaddr_in& UdpContext::getSender() const
{
	return sender;
}

int UdpContext::getSenderLength() const
{
	return senderLength;
}

int UdpContext::getMediaFd() const
{
	return mediaFd;
}

std::string UdpContext::getUser() const
{
	return user;
}

std::string UdpContext::getRegistrationString() const
{
	return registrationString;
}

std::vector<std::string> UdpContext::getRegistrationContents() const
{
	return registrationContents;
}

void UdpContext::setUser(const std::string& user)
{
	this->user = user;
}

void UdpContext::setRegistrationString(const std::string& reg)
{
	this->registrationString = reg;
}

void UdpContext::setRegistrationContents(const std::vector<std::string>& contents)
{
	this->registrationContents = contents;
}