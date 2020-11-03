#include "ServerCommands.hpp"

bool checkTimestamp(const std::string& tsString, Log::TAG tag, const std::string& errorMessage, const std::string& user, const std::string& ip)
{
	Logger* logger = Logger::getInstance();
	try
	{
		const uint64_t timestamp = (uint64_t) std::stoull(tsString); //catch is for this
		const uint64_t maxError = 60L * MARGIN_OF_ERROR;
		const time_t now=time(NULL);
		const uint64_t timeDifference = std::max((uint64_t) now, timestamp) - std::min((uint64_t) now, timestamp);
		if (timeDifference > maxError)
		{
			//only bother processing the command if the timestamp was valid

			//prepare the error log
			const uint64_t mins = timeDifference / 60;
			const uint64_t seconds = timeDifference - mins * 60;
			const std::string error = "timestamp received was outside the " + std::to_string(MARGIN_OF_ERROR) + " minute margin of error: " + std::to_string(mins) + "mins, " + std::to_string(seconds) + "seconds" + errorMessage;
			logger->insertLog(Log(tag, error, user, Log::TYPE::ERROR, ip).toString());
			return false;
		}
	}
	catch(std::invalid_argument &badarg)
	{ //timestamp couldn't be parsed. assume someone is trying something fishy
		logger->insertLog(Log(tag, "invalid_argument: " + errorMessage, user, Log::TYPE::INBOUND, ip).toString());

		const std::string error="INVALID ARGUMENT EXCEPTION: " + errorMessage;
		logger->insertLog(Log(tag, error, user, Log::TYPE::ERROR, ip).toString());

		return false;
	}
	catch(std::out_of_range &exrange)
	{
		logger->insertLog(Log(tag, "out_of_range: " + errorMessage, user, Log::TYPE::INBOUND, ip).toString());

		const std::string error="OUT OF RANGE: " + errorMessage;
		logger->insertLog(Log(tag, error, user, Log::TYPE::ERROR, ip).toString());

		return false;
	}

	return true;
}

bool legitimateAscii(unsigned char* buffer, int length)
{
	for (int i = 0; i < length; i++)
	{
		const unsigned char byte = buffer[i];

		const bool isSign = ((byte == 43) || (byte == 45));
		const bool isNumber = ((byte >= 48) && (byte <= 57));
		const bool isUpperCase = ((byte >= 65) && (byte <= 90));
		const bool isLowerCase = ((byte >= 97) && (byte <= 122));
		const bool isDelimiter = (byte == 124);

		if (!isSign && !isNumber && !isUpperCase && !isLowerCase && !isDelimiter)
		{
			return false;
		}
	}
	return true;
}

//use a vector to prevent reading out of bounds
std::vector<std::string> parse(unsigned char command[])
{
//timestamp|login1|username
//timestamp|login2|username|challenge_decrypted

//session key is always the last one for easy censoring in the logs
//timestamp|call|otheruser|sessionkey
//timestamp|lookup|otheruser|sessionkey
//timestamp|reject|otheruser|sessionkey
//timestamp|accept|otheruser|sessionkey
//timestamp|end|otheruser|sessionkey
//timestamp|passthrough|otheruser|(aes key encrypted)|sessionkey
//timestamp|ready|otheruser|sessionkey

	char* token;
	char* save;
	int i = 0;
	std::vector<std::string> result;
	token = strtok_r((char*)command, "|", &save);
	while(token != NULL && i < COMMAND_MAX_SEGMENTS)
	{
		result.push_back(std::string(token));
		token = strtok_r(NULL, "|", &save);
		i++;
	}
	return result;
}