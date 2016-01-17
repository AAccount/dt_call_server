#include <stdio.h>
#include <stdlib.h>
#include "error.h"

void errorLT0 (int retvalue, const char *msg)
{
	if(retvalue < 0)
	{
		perror(msg);
		exit(1);
	}
}

void errorEQ0(long long retvalue, const char *msg)
{
	if(retvalue == 0)
	{
		perror(msg);
		exit(1);
	}
}
