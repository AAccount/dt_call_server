#include "UdpCommand.hpp"

bool udpDecrypt(UdpContext& ctx, std::unique_ptr<unsigned char[]>& mediaBuffer, int receivedLength)
{
	Logger* logger = ctx.getLogger();
	const std::string ip = std::string(inet_ntoa(ctx.getSender().sin_addr));
	const std::string user = ctx.getUser();

	std::unique_ptr<unsigned char[]> decryptedArray = std::make_unique<unsigned char[]>(MEDIASIZE);
	unsigned char *decrypted = decryptedArray.get(); //extra space will be zeroed creating an automatically zero terminated string
	int unsealok = crypto_box_seal_open(decrypted, mediaBuffer.get(), receivedLength, ctx.getPublicKey().get(), ctx.getPrivateKey().get());
	if (unsealok != 0)
	{
		const std::string error = "udp bad unseal";
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user, Log::TYPE::ERROR, ip).toString());
		return false; //bad registration
	}

	std::string registration((char *)decrypted);
	if (!legitimateAscii((unsigned char *)registration.c_str(), registration.length()))
	{
		const std::string error = "udp unseal ok, bad ascii";
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user, Log::TYPE::ERROR, ip).toString());
		return false; //bad characters in registration
	}

	std::string ogregistration = registration;
	std::vector<std::string> registrationParsed = parse((unsigned char *)registration.c_str());
	if (registrationParsed.size() != REGISTRATION_SEGMENTS)
	{
		const std::string error = "udp unseal ok, ascii ok, bad format: " + ogregistration;
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user, Log::TYPE::ERROR, ip).toString());
		return false; //improperly formatted registration
	}	

	ctx.setRegistrationContents(registrationParsed);
	ctx.setRegistrationString(ogregistration);
	return true;
}

void udpRegister(UdpContext& ctx, std::unordered_map<int, std::unique_ptr<Client>>& clientMap)
{
	UserUtils* userUtils = ctx.getUserUtils();
	Logger* logger = ctx.getLogger();
	const struct sockaddr_in& sender = ctx.getSender();
	const std::string summary = std::string(inet_ntoa(sender.sin_addr)) + ":" + std::to_string(ntohs(sender.sin_port));
	const std::string ip = std::string(inet_ntoa(sender.sin_addr));
	std::string ogRegistration = ctx.getRegistrationString();
	std::vector<std::string> registrationParsed = ctx.getRegistrationContents();

	const std::string sessionkey = registrationParsed.at(1);
	std::string user = userUtils->userFromSessionKey(sessionkey);
	const bool timestampOK = checkTimestamp(registrationParsed.at(0), Log::TAG::UDPTHREAD, ogRegistration, user, ip);
	if (!timestampOK)
	{
		const std::string error = "udp unseal ok, ascii ok, format ok, bad timestamp " + ogRegistration;
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user, Log::TYPE::ERROR, ip).toString());
		return;
	}

	//bogus session key
	if (user == "")
	{
		const std::string error = "udp registration key doesn't belong to anyone " + ogRegistration;
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user, Log::TYPE::ERROR, ip).toString());
		return;
	}

	//user is somebody, set the udp info
	userUtils->setUdpSummary(sessionkey, summary);
	userUtils->setUdpInfo(sessionkey, sender);

	//if the person is not in a call, there is no need to register a media port
	if (userUtils->getCallWith(user) == "")
	{
		userUtils->clearUdpInfo(user);
		return;
	}

	ctx.setUser(user);
	udpAck(ctx, clientMap);
}

void udpAck(UdpContext& ctx, std::unordered_map<int, std::unique_ptr<Client>>& clientMap)
{
	UserUtils* userUtils = ctx.getUserUtils();
	Logger* logger = ctx.getLogger();
	const struct sockaddr_in sender = ctx.getSender();
	const std::string ip = std::string(inet_ntoa(sender.sin_addr));
	const std::string user = ctx.getUser();

	//create and encrypt ack
	const time_t now = time(NULL);
	const std::string ack = std::to_string(now);
	std::unique_ptr<unsigned char[]> ackEnc = std::make_unique<unsigned char[]>(COMMANDSIZE);
	int encLength = 0;
	const int userCmdPort = userUtils->getCommandFd(user);
	const std::unique_ptr<unsigned char[]> &userTCPKey = clientMap[userCmdPort]->getSymmetricKey();
	SodiumUtils::sodiumEncrypt(false, (unsigned char *)ack.c_str(), ack.length(), userTCPKey.get(), NULL, ackEnc, encLength);

	//encryption failed??
	if (encLength == 0)
	{
		const std::string error = "failed to sodium encrypt udp ack???\n";
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user, Log::TYPE::ERROR, ip).toString());
		return;
	}

	//send udp ack: no time like the present to test the 2 way udp connection
	const int sent = sendto(ctx.getMediaFd(), ackEnc.get(), encLength, 0, (struct sockaddr*)&sender, ctx.getSenderLength());
	if (sent < 0)
	{
		const std::string error = "udp sendto failed during media port registration with errno (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		logger->insertLog(Log(Log::TAG::UDPTHREAD, error, user, Log::TYPE::ERROR, ip).toString());
	}
}

void udpCall(UdpContext& ctx, std::unique_ptr<unsigned char[]> &mediaBuffer, int receivedLength)
{
	UserUtils* userUtils = ctx.getUserUtils();
	std::string user = ctx.getUser();

	//in call, passthrough audio untouched (end to end encryption if only to avoid touching more openssl apis)
	const std::string otherPerson = userUtils->getCallWith(user);

	//if the other person disappears midway through, calling clear session on his socket will cause
	//	you to have nobody listed in User.callWith (or "" default value). getUdpInfo("") won't end well
	if (otherPerson == "")
	{
		return;
	}

	struct sockaddr_in otherSocket = userUtils->getUdpInfo(otherPerson);
	const int sent = sendto(ctx.getMediaFd(), mediaBuffer.get(), receivedLength, 0, (struct sockaddr*)&otherSocket, sizeof(otherSocket));
	if (sent < 0)
	{
		const std::string error = "udp sendto failed during live call with errno (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		const std::string ip = std::string(inet_ntoa(otherSocket.sin_addr));
		ctx.getLogger()->insertLog(Log(Log::TAG::UDPTHREAD, error, user, Log::TYPE::ERROR, ip).toString());
	}
}