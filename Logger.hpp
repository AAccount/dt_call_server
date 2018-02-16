/*
 * Logger.hpp
 *
 *  Created on: Sep 29, 2017
 *      Author: Daniel
 */

#ifndef LOGGER_HPP_
#define LOGGER_HPP_

#include <fstream>
#include <queue>
#include <pthread.h>
#include <string.h>

#include "Log.hpp"
#include "const.h"

class Logger
{
public:
	static Logger* getInstance();
	void insertLog(Log l);

private:
	static Logger *instance;
	Logger();
	virtual ~Logger();

	//output log (changed every 24 hours)
	static std::ofstream *logfile;
	static time_t logTimeT;

	//log disk writing thread stuff
	static pthread_t diskThread;
	static pthread_mutex_t qMutex;
	static pthread_cond_t wakeup;
	static void* diskRw(void *ignored);
	static std::queue<Log> backlog;
};

#endif /* LOGGER_HPP_ */