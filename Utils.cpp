/*
 * Utils.cpp
 *
 *  Created on: Aug 14, 2016
 *      Author: Daniel
 */

#include "Utils.hpp"
#include <time.h>
#include <stdint.h>

//https://stackoverflow.com/questions/3756323/getting-the-current-time-in-milliseconds
uint64_t Utils::millisNow()
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);

	//must assign the value to the uint64_t first BEFORE modifying it.
	//if assign and modification are one shotted, then the result is garbage for 32bit cpus.
	uint64_t seconds = now.tv_sec;
	seconds = seconds * 1000;
	uint64_t nanos = now.tv_nsec;
	nanos = (uint64_t)nanos/1.0e6;

	uint64_t result = seconds + nanos;
	return result ;
}
