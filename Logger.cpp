/*
 * Logger.cpp
 *
 *  Created on: Sep 29, 2017
 *      Author: Daniel
 */

#include "Logger.hpp"

time_t Logger::logTimeT;
std::ofstream *Logger::logfile;
pthread_t Logger::diskThread;
pthread_mutex_t Logger::qMutex;
pthread_cond_t Logger::wakeup;
std::queue<Log> Logger::backlog;
Logger* Logger::instance = NULL;

Logger* Logger::getInstance()
{
	if(instance == NULL)
	{
		instance = new Logger();
	}
	return instance;
}

Logger::Logger()
{
	//setup the log output
	//(ok to stall the program here as you need the log initialized before you can do anything)
	logTimeT = time(NULL);
	std::string nowString = std::string(ctime(&logTimeT));
	std::string logName = LOGPREFIX() + nowString.substr(0, nowString.length()-1);
	logfile = new std::ofstream(LOGFOLDER()+logName);

	//keep disk IO on its own thread. don't know what kind of disk you'll get
	//don't let a slow disk stall the whole program just for logging.
	pthread_mutex_init(&qMutex, NULL);
	pthread_cond_init(&wakeup, NULL);
	if (pthread_create(&diskThread, NULL, diskRw, NULL) != 0)
	{
		std::string error = "cannot create the disk rw thread (" + std::to_string(errno) + ") " + std::string(strerror(errno));
		exit(1);
	}

}

Logger::~Logger()
{
	delete logfile;
}

void* Logger::diskRw(void *ignored)
{
	while(true)
	{
		pthread_mutex_lock(&qMutex);
			bool empty = backlog.empty();
		pthread_mutex_unlock(&qMutex);

		while(!empty)
		{
			//get the next log item
			pthread_mutex_lock(&qMutex);
				Log log = backlog.front();
				backlog.pop();
				empty = backlog.empty();
			pthread_mutex_unlock(&qMutex);

			//figure out if the current log is over 1 day old
			time_t now = time(NULL);
			if((now - logTimeT) > 60*60*24)
			{//if the log is too old, close it and start another one
				logfile->close();
				logTimeT = now;
				std::string nowString = std::string(ctime(&logTimeT));
				std::string logName = LOGPREFIX() + nowString.substr(0, nowString.length()-1);
				logfile->open(LOGFOLDER()+logName);
			}
			*(logfile) << log << "\n";
			logfile->flush(); // write immediately to the file

			if(log.getType() == Log::TYPE::ERROR)
			{//make errors dead obvious when testing
				std::cerr << log << "\n";
			}
			else
			{
				std::cout << log << "\n";
			}
		}

		//no more logs to write? wait until there is one
#ifdef VERBOSE
		std::cout << "DISK RW: nothing to write\n";
#endif
		while(backlog.empty())
		{
			pthread_cond_wait(&wakeup, &qMutex);
#ifdef VERBOSE
			std::cout << "DISK RW: woken up to write\n";
#endif
		}
		pthread_mutex_unlock(&qMutex);
	}
}

void Logger::insertLog(Log dbl)
{
	//put a new log in the backlog
	pthread_mutex_lock(&qMutex);
		backlog.push(dbl);
	pthread_mutex_unlock(&qMutex);

	pthread_cond_signal(&wakeup);
}
