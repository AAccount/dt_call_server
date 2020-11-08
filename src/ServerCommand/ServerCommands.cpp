#include "ServerCommands.hpp"

bool ServerCommand::decrypt(CommandContext& ctx, const std::unique_ptr<unsigned char[]>& inputBuffer, int length, const std::unique_ptr<unsigned char[]>& symmetricKey, std::string& ogCommand, std::vector<std::string>& commandContents)
{
	int decLength = 0;
	std::unique_ptr<unsigned char[]> decBuffer = std::make_unique<unsigned char[]>(COMMANDSIZE);
	SodiumUtils::sodiumDecrypt(false, inputBuffer.get(), length, symmetricKey.get(), NULL, decBuffer, decLength);
	if (decLength == 0)
	{
		return false;
	}

	if (!CommandUtils::legitimateAscii(decBuffer.get(), decLength))
	{
		const std::string unexpected = "unexpected byte in string";
		const std::string ip = ipFromFd(ctx.getFd());
		ctx.getLogger()->insertLog(Log(Log::TAG::BADCMD, unexpected, ctx.getUser(), Log::TYPE::ERROR, ip).toString());
		return false;
	}

	//periodically sent for nat purposes
	std::string bufferCmd((char *)decBuffer.get(), decLength);
	if (bufferCmd == JBYTE)
	{
		return false;
	}
	ogCommand= bufferCmd; //copy bufferCmd to another string before strtok messes up the original
	commandContents = CommandUtils::parse((unsigned char *)bufferCmd.c_str());

	const std::string user = ctx.getUser();
	const std::string ip = ipFromFd(ctx.getFd());
	const int segments = commandContents.size();
	if (segments < COMMAND_MIN_SEGMENTS || segments > COMMAND_MAX_SEGMENTS)
	{
		ctx.getLogger()->insertLog(Log(Log::TAG::BADCMD, ogCommand + "\nbad amount of command segments: " + std::to_string(segments), user, Log::TYPE::ERROR, ip).toString());
		return false;
	}

	const bool timestampOK = CommandUtils::checkTimestamp((const std::string &)commandContents.at(0), Log::TAG::BADCMD, ogCommand, user, ip);
	if (!timestampOK)
	{
		//checkTimestamp will logg an error
		return false;
	}

	UserUtils* userUtils = ctx.getUserUtils();
	const std::string command = commandContents.at(1);
	const std::string sessionkey = commandContents.at(commandContents.size() - 1);
	if ((command != "login1") && (command != "login2") && (!userUtils->verifySessionKey(sessionkey, ctx.getFd())))
	{
		const std::string error = "INVALID SESSION ID. refusing command (" + ogCommand + ")";
		ctx.getLogger()->insertLog(Log(Log::TAG::BADCMD, error, user, Log::TYPE::ERROR, ip).toString());

		const std::string invalid = CommandUtils::unixTs() + "|invalid";
		write2Client(ctx, invalid, ctx.getFd());
		ctx.getLogger()->insertLog(Log(Log::TAG::BADCMD, invalid, user, Log::TYPE::OUTBOUND, ip).toString());
		return false;
	}

	if ((command != "login1") && (command != "login2"))
	{
		ogCommand.replace(ogCommand.find(sessionkey), SESSION_KEY_LENGTH, SESSION_KEY_PLACEHOLDER);
	}
	
	return true;
}

//if it is a new/first time client, send the "SSL key"
/**
	* This setup should me MitM safe.
	* Assume: client public key --> middle man catch, send middle man public key --> server
	* On the server: server sign with server's key encrypt with middle man --> middle man
	* 	middle man decrypts tcp session key --> can't send to client because he can't sign as the server
	* Clients are required to have the server's public sodium key ahead of time.
 */
void ServerCommand::initClient(CommandContext& ctx, const std::unique_ptr<unsigned char[]>& inputBufferArray, int amountRead, const std::unique_ptr<unsigned char[]>& sodiumPublicKey, const std::unique_ptr<unsigned char[]>& sodiumPrivateKey)
{
	const std::string ip = ipFromFd(ctx.getFd());
	std::unique_ptr<unsigned char[]> decryptedInputBuffer = std::make_unique<unsigned char[]>(COMMANDSIZE);//need to have space for malicious input that may be as long as the whole buffer
	unsigned char* initialTempPublic = decryptedInputBuffer.get(); //extra space will be zeroed
	int unsealok = crypto_box_seal_open(initialTempPublic, inputBufferArray.get(), amountRead, sodiumPublicKey.get(), sodiumPrivateKey.get());
	if(unsealok != 0)
	{
		const std::string error = "bad initial sodium socket setup";
		ctx.getLogger()->insertLog(Log(Log::TAG::INCOMINGCMD, error, Log::DONTKNOW() , Log::TYPE::ERROR, ip).toString());
		ctx.getRemovals().push_back(ctx.getFd());
		return;
	}

	//send the equivalent of the SSL key
	std::unique_ptr<unsigned char[]> encTCPKey = std::make_unique<unsigned char[]>(COMMANDSIZE);
	int encTCPKeyLength = 0;
	SodiumUtils::sodiumEncrypt(true, ctx.getClient()->getSymmetricKey().get(), crypto_secretbox_KEYBYTES, sodiumPrivateKey.get(), initialTempPublic, encTCPKey, encTCPKeyLength);
	if(encTCPKeyLength > 0)
	{
		const int errValue = write(ctx.getFd(), encTCPKey.get(), encTCPKeyLength);
		if(errValue == -1)
		{
			const std::string error = "initial sodium socket setup write errno " + ServerUtils::printErrno();
			ctx.getLogger()->insertLog(Log(Log::TAG::TCP, error, Log::DONTKNOW(), Log::TYPE::ERROR, ip).toString());
			ctx.getRemovals().push_back(ctx.getFd());
		}
		ctx.getClient()->hasBeenSeen();
	}
	else //sodium encrypted command socket failed. the client can try again
	{
		ctx.getRemovals().push_back(ctx.getFd());
	}
}

void ServerCommand::login1(CommandContext& ctx, const std::unique_ptr<unsigned char[]>& sodiumPrivateKey)
{
	Logger* logger = ctx.getLogger();
	UserUtils* userUtils = ctx.getUserUtils();
	const int fd = ctx.getFd();
	const std::string ip = ipFromFd(fd);

	//timestamp|login1|username
	const std::string username = ctx.getCommandContents().at(2);
	logger->insertLog(Log(Log::TAG::LOGIN, ctx.getOriginalBufferString(), username, Log::TYPE::INBOUND, ip).toString());

	//don't immediately remove old command fd. this would allow anyone
	//	to send a login1 command and kick out a legitimately logged in person.

	unsigned char userSodiumPublic[crypto_box_PUBLICKEYBYTES] = {};
	if (!userUtils->getSodiumPublicKey(username, userSodiumPublic))
	{
		const std::string invalid = CommandUtils::unixTs() + "|invalid";
		logger->insertLog(Log(Log::TAG::LOGIN, invalid, username, Log::TYPE::OUTBOUND, ip).toString());
		write2Client(ctx, invalid, fd);
		ctx.getRemovals().push_back(fd); //nothing useful can come from this socket
		return;
	}

	const std::string challenge = SodiumUtils::randomString(CHALLENGE_LENGTH);
	userUtils->setChallenge(username, challenge);

	int encLength = 0;
	std::unique_ptr<unsigned char[]> enc = std::make_unique<unsigned char[]>(COMMANDSIZE);
	SodiumUtils::sodiumEncrypt(true, (unsigned char *)(challenge.c_str()), challenge.length(), sodiumPrivateKey.get(), userSodiumPublic, enc, encLength);
	if (encLength < 1)
	{
		logger->insertLog(Log(Log::TAG::LOGIN, "sodium encryption of the challenge failed", username, Log::TYPE::ERROR, ip).toString());
		return;
	}
	const std::string encString = Stringify::stringify(enc.get(), encLength);

	const std::string resp = CommandUtils::unixTs() + "|login1resp|" + encString;
	write2Client(ctx, resp, fd);
	logger->insertLog(Log(Log::TAG::LOGIN, resp, username, Log::TYPE::OUTBOUND, ip).toString());
}

void ServerCommand::login2(CommandContext& ctx)
{
	Logger* logger = ctx.getLogger();
	UserUtils* userUtils = ctx.getUserUtils();
	std::vector<int>& removals = ctx.getRemovals();
	const std::vector<std::string> commandContents = ctx.getCommandContents();
	const int fd = ctx.getFd();
	const std::string ip = ipFromFd(fd);

	//timestamp|login2|username|challenge|keepudp(optional)

	//ok to store challenge answer in the log. challenge is single use, disposable
	const std::string username = commandContents.at(2);
	logger->insertLog(Log(Log::TAG::LOGIN, ctx.getOriginalBufferString(), username, Log::TYPE::INBOUND, ip).toString());
	const std::string triedChallenge = commandContents.at(3);

	//check the challenge
	//	an obvious loophole: send "" as the challenge since that's the default value
	//	DON'T accept the default ""
	const std::string answer = userUtils->getChallenge(username);
	if (answer == "" || triedChallenge != answer)
	{
		const std::string invalid = CommandUtils::unixTs() + "|invalid";
		logger->insertLog(Log(Log::TAG::LOGIN, invalid, username, Log::TYPE::OUTBOUND, ip).toString());
		write2Client(ctx, invalid, fd);
		removals.push_back(fd); 

		userUtils->setChallenge(username, "");
		return;
	}

	//for authenticated connections, allow more timeout in case of bad internet
	struct timeval authTimeout;
	authTimeout.tv_sec = AUTHTIMEOUT;
	authTimeout.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&authTimeout, sizeof(authTimeout)) < 0)
	{
		const std::string error = "cannot set timeout for authenticated command socket " + ServerUtils::printErrno();
		logger->insertLog(Log(Log::TAG::LOGIN, error, Log::SELF(), Log::TYPE::ERROR, ip).toString());
	}

	//now that the person has successfully logged in, remove the old information.
	//	this person has established new connections so it's 100% sure the old ones aren't	needed anymore.
	const int oldcmd = userUtils->getCommandFd(username);
	if (oldcmd > 0)
	{ //remove old SSL structs to prevent memory leak
		removals.push_back(oldcmd);
	}

	//dissociate old fd from user otherwise the person will have 2 commandfds listed in
	//	comamandfdMap. remove client will see the old fd pointing to the user and will clear
	//	the user's session key and fds. don't want them cleared as they're now the new ones.
	//	immediately clean up this person's records before all the new stuff goes in
	bool keepudp = false;
	if (commandContents.size() == 5 && commandContents.at(4) == "keepudp")
	{
		keepudp = true;
	}

	if (!keepudp)
	{
		//for cases where you were in a call but your connection died. call record will still be there
		//	since you didn't formally send a call end
		const std::string other = userUtils->getCallWith(username);
		if (other != "")
		{
			sendCallEnd(ctx, other);
		}
	}
	userUtils->clearSession(username, keepudp);

	const std::string sessionkey = SodiumUtils::randomString(SESSION_KEY_LENGTH);
	userUtils->setSessionKey(username, sessionkey);
	userUtils->setCommandFd(sessionkey, fd);
	userUtils->setChallenge(username, ""); //reset after successful completion

	std::string resp = CommandUtils::unixTs() + "|login2resp|" + sessionkey;
	write2Client(ctx, resp, fd);
	resp = CommandUtils::unixTs() + "|login2resp|" + SESSION_KEY_PLACEHOLDER;
	logger->insertLog(Log(Log::TAG::LOGIN, resp, username, Log::TYPE::OUTBOUND, ip).toString());
}

//all (non login) commands have the format timestamp|COMMAND|(stuff)...sessionkey
//variables written from touma calling zapper perspective
//command will come from touma's cmd fd
void ServerCommand::call(CommandContext& ctx)
{
	Logger* logger = ctx.getLogger();
	UserUtils* userUtils = ctx.getUserUtils();
	const std::vector<std::string> commandContents = ctx.getCommandContents();
	const int fd = ctx.getFd();
	const std::string ip = ipFromFd(fd);

	//timestamp|call|zapper|toumakey

	const std::string zapper = commandContents.at(2);
	const std::string touma = ctx.getUser();
	logger->insertLog(Log(Log::TAG::CALL, ctx.getOriginalBufferString(), touma, Log::TYPE::INBOUND, ip).toString());
	const int zapperCmdFd = userUtils->getCommandFd(zapper);

	//find out if zapper has a command fd (signed in)
	const bool offline = (zapperCmdFd == 0);
	//make sure zapper isn't already in a call or waiting for one to connect
	const bool busy = (userUtils->getCallWith(zapper) != "");
	//make sure touma didn't accidentally dial himself
	const bool selfDial = (touma == zapper);

	if (offline || busy || selfDial)
	{
		const std::string na = CommandUtils::unixTs() + "|end|" + zapper;
		write2Client(ctx, na, fd);
		logger->insertLog(Log(Log::TAG::CALL, na, touma, Log::TYPE::OUTBOUND, ip).toString());
		return; //nothing more to do
	}

	//setup the user statuses and register the call with user utils
	userUtils->setUserState(zapper, INIT);
	userUtils->setUserState(touma, INIT);
	userUtils->setCallPair(touma, zapper);

	//tell touma that zapper is being rung
	const std::string notifyTouma = CommandUtils::unixTs() + "|available|" + zapper;
	write2Client(ctx, notifyTouma, fd);
	logger->insertLog(Log(Log::TAG::CALL, notifyTouma, touma, Log::TYPE::OUTBOUND, ip).toString());

	//tell zapper touma wants to call her
	const std::string notifyZapper = CommandUtils::unixTs() + "|incoming|" + touma;
	write2Client(ctx, notifyZapper, zapperCmdFd);
	const std::string zapperip = ipFromFd(zapperCmdFd);
	logger->insertLog(Log(Log::TAG::CALL, notifyZapper, zapper, Log::TYPE::OUTBOUND, zapperip).toString());
}

//variables written when zapper accepts touma's call
//command will come from zapper's cmd fd
void ServerCommand::accept(CommandContext& ctx)
{
	Logger* logger = ctx.getLogger();
	UserUtils* userUtils = ctx.getUserUtils();
	const std::vector<std::string> commandContents = ctx.getCommandContents();
	const int fd = ctx.getFd();
	const std::string ip = ipFromFd(fd);

	//timestamp|accept|touma|zapperkey
	const std::string zapper = ctx.getUser();
	const std::string touma = commandContents.at(2);
	logger->insertLog(Log(Log::TAG::ACCEPT, ctx.getOriginalBufferString(), zapper, Log::TYPE::INBOUND, ip).toString());

	if (!isRealCall(ctx, zapper, touma, Log::TAG::ACCEPT))
	{
		return;
	}

	//arbitrarily chosen that the one who makes the call (touma) gets to generate the aes key
	const int toumaCmdFd = userUtils->getCommandFd(touma);
	const std::string toumaResp = CommandUtils::unixTs() + "|prepare|" + userUtils->getSodiumKeyDump(zapper) + "|" + zapper;
	write2Client(ctx, toumaResp, toumaCmdFd);
	logger->insertLog(Log(Log::TAG::ACCEPT, toumaResp, touma, Log::TYPE::OUTBOUND, ipFromFd(toumaCmdFd)).toString());

	//send zapper touma's public key to be able to verify that the aes256 passthrough is actually from him
	const std::string zapperResp = CommandUtils::unixTs() + "|prepare|" + userUtils->getSodiumKeyDump(touma) + "|" + touma;
	write2Client(ctx, zapperResp, fd);
	logger->insertLog(Log(Log::TAG::ACCEPT, zapperResp, zapper, Log::TYPE::OUTBOUND, ip).toString());
}

void ServerCommand::passthrough(CommandContext& ctx)
{
	Logger* logger = ctx.getLogger();
	UserUtils* userUtils = ctx.getUserUtils();
	const std::vector<std::string> commandContents = ctx.getCommandContents();
	const int fd = ctx.getFd();
	const std::string ip = ipFromFd(fd);
	std::string originalBufferCmd = ctx.getOriginalBufferString();

	//timestamp|passthrough|zapper|encrypted aes key|toumakey
	const std::string zapper = commandContents.at(2);
	const std::string touma = ctx.getUser();
	const std::string end2EndKeySetup = commandContents.at(3);
	originalBufferCmd.replace(originalBufferCmd.find(end2EndKeySetup), end2EndKeySetup.length(), AES_PLACEHOLDER);
	logger->insertLog(Log(Log::TAG::PASSTHROUGH, originalBufferCmd, ctx.getUser(), Log::TYPE::INBOUND, ip).toString());

	if (!isRealCall(ctx, touma, zapper, Log::TAG::PASSTHROUGH))
	{
		return;
	}

	const int zapperfd = userUtils->getCommandFd(zapper);
	std::string direct = CommandUtils::unixTs() + "|direct|" + end2EndKeySetup + "|" + touma; //as in "directly" from touma, not from the server
	write2Client(ctx, direct, zapperfd);
	direct.replace(direct.find(end2EndKeySetup), end2EndKeySetup.length(), AES_PLACEHOLDER);
	logger->insertLog(Log(Log::TAG::PASSTHROUGH, direct, zapper, Log::TYPE::OUTBOUND, ipFromFd(zapperfd)).toString());
}

void ServerCommand::ready(CommandContext& ctx)
{
	Logger* logger = ctx.getLogger();
	UserUtils* userUtils = ctx.getUserUtils();
	const std::vector<std::string> commandContents = ctx.getCommandContents();
	const int fd = ctx.getFd();
	const std::string ip = ipFromFd(fd);
	std::string originalBufferCmd = ctx.getOriginalBufferString();

	//timestamp|ready|touma|zapperkey
	const std::string zapper = ctx.getUser();
	const std::string touma = commandContents.at(2);
	logger->insertLog(Log(Log::TAG::READY, originalBufferCmd, ctx.getUser(), Log::TYPE::INBOUND, ip).toString());
	if (!isRealCall(ctx, zapper, touma, Log::TAG::READY))
	{
		return;
	}

	userUtils->setUserState(zapper, INCALL);
	if (userUtils->getUserState(touma) == INCALL)
	{ //only if both people are ready can  you start the call

		//tell touma zapper accepted his call request
		//	AND confirm to touma, it's zapper he's being connected with
		const int toumaCmdFd = userUtils->getCommandFd(touma);
		const std::string toumaResp = CommandUtils::unixTs() + "|start|" + zapper;
		write2Client(ctx, toumaResp, toumaCmdFd);
		logger->insertLog(Log(Log::TAG::ACCEPT, toumaResp, touma, Log::TYPE::OUTBOUND, ipFromFd(toumaCmdFd)).toString());

		//confirm to zapper she's being connected to touma
		const std::string zapperResp = CommandUtils::unixTs() + "|start|" + touma;
		write2Client(ctx, zapperResp, fd);
		logger->insertLog(Log(Log::TAG::ACCEPT, zapperResp, zapper, Log::TYPE::OUTBOUND, ip).toString());
	}
}

void ServerCommand::end(CommandContext& ctx)
{
	const std::string ip = ipFromFd(ctx.getFd());

	//timestamp|end|zapper|toumakey
	const std::string zapper = ctx.getCommandContents().at(2);
	const std::string touma = ctx.getUser();
	ctx.getLogger()->insertLog(Log(Log::TAG::END, ctx.getOriginalBufferString(), touma, Log::TYPE::INBOUND, ip).toString());

	if (!isRealCall(ctx, touma, zapper, Log::TAG::END))
	{
		return;
	}

	sendCallEnd(ctx, zapper);
}

//before doing an accept, reject, end command check to see if it's for a real call
//	or someone trying to get smart with the server
bool ServerCommand::isRealCall(CommandContext& ctx, const std::string& persona, const std::string& personb, Log::TAG tag)
{
	Logger* logger = ctx.getLogger();

	bool real = true;
	UserUtils* userUtils = ctx.getUserUtils();
	const std::string awith = userUtils->getCallWith(persona);
	const std::string bwith = userUtils->getCallWith(personb);
	if((awith == "") || (bwith == ""))
	{
		real = false;
	}

	if((persona != bwith) || (personb != awith))
	{
		real = false;
	}

	if(!real)
	{
		const int fd = userUtils->getCommandFd(persona);
		const std::string ip = ipFromFd(fd);
		const std::string error = persona + " sent a command for a nonexistant call";
		logger->insertLog(Log(tag, error, persona, Log::TYPE::ERROR, ip).toString());

		const std::string invalid = CommandUtils::unixTs() + "|invalid";
		if(fd > 0)
		{
			write2Client(ctx, invalid, fd);
			logger->insertLog(Log(tag, invalid, persona, Log::TYPE::OUTBOUND, ip).toString());
		}
	}
	return real;
}

// write a message to a client
void ServerCommand::write2Client(CommandContext& ctx, const std::string& response, int sd)
{
	Logger* logger = ctx.getLogger();
	std::unordered_map<int, std::unique_ptr<Client>>& clients = ctx.getClientMap();

	//in case the client disappears suddenly
	if(clients.count(sd) == 0)
	{
		return;
	}

	std::unique_ptr<unsigned char[]> encOutput = std::make_unique<unsigned char[]>(COMMANDSIZE);
	int encOutputLength = 0;
	const std::unique_ptr<Client>& client = clients[sd];

	SodiumUtils::sodiumEncrypt(false, (unsigned char*)(response.c_str()), response.length(), client->getSymmetricKey().get(), NULL, encOutput, encOutputLength);
	const int errValue = write(sd, encOutput.get(), encOutputLength);

	if(errValue == -1)
	{
		UserUtils* userUtils = UserUtils::getInstance();
		const std::string user = userUtils->userFromCommandFd(sd);
		const std::string ip = ipFromFd(sd);
		const std::string error = "write2Client " + ServerUtils::printErrno();
		logger->insertLog(Log(Log::TAG::TCP, error, user, Log::TYPE::ERROR, ip).toString());
	}
}

std::string ServerCommand::ipFromFd(int sd)
{
	struct sockaddr_in thisfd;
	socklen_t thisfdSize = sizeof(struct sockaddr_in);
	const int result = getpeername(sd, (struct sockaddr*) &thisfd, &thisfdSize);
	if(result == 0)
	{
		return std::string(inet_ntoa(thisfd.sin_addr));
	}
	else
	{
		return "ipFromFd " + ServerUtils::printErrno();
	}
}

void ServerCommand::sendCallEnd(CommandContext& ctx, const std::string& user)
{
	Logger* logger = ctx.getLogger();

	//reset both peoples's states and remove the call pair record
	UserUtils* userUtils = ctx.getUserUtils();
	const std::string other = userUtils->getCallWith(user);
	userUtils->setUserState(user, NONE);
	userUtils->setUserState(other, NONE);
	userUtils->removeCallPair(user);

	//send the call end
	const std::string resp = CommandUtils::unixTs() + "|end|" + other;
	const int cmdFd = userUtils->getCommandFd(user);
	write2Client(ctx, resp, cmdFd);
	logger->insertLog(Log(Log::TAG::END, resp, user, Log::TYPE::OUTBOUND, ipFromFd(cmdFd)).toString());
}

