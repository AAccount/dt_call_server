/*
 * stringify.hpp
 *
 *  Created on: Dec 15, 2018
 *      Author: Daniel
 */

#ifndef STRINGIFY_HPP_
#define STRINGIFY_HPP_

#include <iostream>
#include <string>
#include <sodium.h>

namespace Stringify
{
	//turn unsigned char array into/out of string of #s
	std::string stringify(unsigned char* bytes, int length);
	void destringify(const std::string& input, unsigned char* output);
}
#endif /* STRINGIFY_HPP_ */
