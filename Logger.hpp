/*
 * Logger.hpp
 *
 *  Created on: Sep 29, 2017
 *      Author: Daniel
 */

#ifndef LOGGER_HPP_
#define LOGGER_HPP_

#include <iostream>
#include <fstream>
#include <queue>
#include <pthread.h>
#include <string.h>
#include "BlockingQ.hpp"

class Logger
{
public:
	static Logger* getInstance(const std::string& folder);
	void insertLog(const std::string& l);

private:
	static Logger* instance;
	explicit Logger(const std::string& cfolder);
	virtual ~Logger();

	//output log (changed every 24 hours)
	std::ofstream logfile;
	time_t logTimeT;
	const std::string folder;

	BlockingQ<std::string> q;

	//log disk writing thread stuff
	static void* diskRw(void* context);

	//don't allow copying the logger. there is only the 1
	Logger(const Logger&) = delete;

	const static std::string& LOGPREFIX();
};

#endif /* LOGGER_HPP_ */
