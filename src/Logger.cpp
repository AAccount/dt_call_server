/*
 * Logger.cpp
 *
 *  Created on: Sep 29, 2017
 *      Author: Daniel
 */

#include "Logger.hpp"
#include "Utils.hpp"

Logger* Logger::instance = NULL;
std::string Logger::logLocation;
bool Logger::alreadySetLogLocation = false;

void Logger::setLogLocation(const std::string& folder)
{
	if(!alreadySetLogLocation)
	{
		logLocation = folder;
	}
	alreadySetLogLocation = true;
}

const std::string& Logger::LOGPREFIX()
{
	const static std::string value = "log ";
	return value;
}

Logger* Logger::getInstance()
{
	if(instance == NULL)
	{
		instance = new Logger();
	}
	return instance;
}

Logger::Logger() :
folder(logLocation),
logTimeT(time(NULL)),
q(BlockingQ<std::string>())
{
	if(!Utils::fileExists(logLocation))
	{
		std::cerr << "Log folder doesn't exist: " << logLocation << "\n";
		exit(1);
	}
	
	const std::string nowString = std::string(ctime(&logTimeT));
	const std::string logName = LOGPREFIX() + nowString.substr(0, nowString.length()-1);
	logfile = std::ofstream(folder+"/"+logName);

	pthread_t diskThread;
	if (pthread_create(&diskThread, NULL, diskRw, this) != 0) //have to pass "this", instance won't be available until the constructor exits
	{
		std::cerr << "cannot create the disk rw thread (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		exit(1);
	}

}

Logger::~Logger()
{
	logfile.flush();
	logfile.close();
}

void* Logger::diskRw(void* context)
{
	Logger* self = static_cast<Logger*>(context);
	while(true)
	{
		const std::string log = self->q.pop();

		//figure out if the current log is over 1 day old
		const time_t now = time(NULL);
		if((now - self->logTimeT) > 60*60*24)
		{//if the log is too old, close it and start another one
			self->logfile.close();
			self->logTimeT = now;
			const std::string nowString = std::string(ctime(&self->logTimeT));
			const std::string logName = LOGPREFIX() + nowString.substr(0, nowString.length()-1);
			self->logfile.open(self->folder+"/"+logName);
		}
		self->logfile << log << "\n";
		self->logfile.flush(); // write immediately to the file

		std::cout << log << "\n";
	}
}

void Logger::insertLog(const std::string& dbl)
{
	q.push(dbl);
}
