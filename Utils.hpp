/*
 * Utils.hpp
 *
 *  Created on: Aug 14, 2016
 *      Author: Daniel
 *
 *  Common stuff used by multiple files
 */

#ifndef UTILS_HPP_
#define UTILS_HPP_
#include <stdint.h>

class Utils
{
	public:
		//get the time now in milliseconds
		static uint64_t millisNow();
};

#endif /* UTILS_HPP_ */
