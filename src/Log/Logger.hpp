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
#include <thread>
#include <filesystem>
#include <string.h>
#include "BlockingQ.hpp"
#include "../ServerUtils.hpp"

class Logger
{
public:
	static void setLogLocation(const std::string& folder);
	static Logger* getInstance();
	void insertLog(const std::string& l);

private:
	static Logger* instance;
	explicit Logger();
	virtual ~Logger();
	static bool alreadySetLogLocation;
	static std::string logLocation;

	//output log (changed every 24 hours)
	std::ofstream logfile;
	time_t logTimeT;
	const std::string folder;

	BlockingQ<std::string> q;

	//log disk writing thread stuff
	void diskRw();

	//don't allow copying the logger. there is only the 1
	Logger(const Logger&) = delete;

	inline const static std::string LOGPREFIX = "log ";
};

#endif /* LOGGER_HPP_ */
