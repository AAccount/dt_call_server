#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "libscrypt.h"

#define MAXPASS 1000

int main(int argc, char *argv[])
{
	char plaintext[MAXPASS];
	printf("Enter password to be scrypt-ed: ");
	if(fgets(plaintext, 1000, stdin))
	{
		plaintext[strlen(plaintext)-1] = 0;
		char hashtext[MAXPASS];
		if(libscrypt_hash(hashtext, plaintext, SCRYPT_N, SCRYPT_r, SCRYPT_p))
		{
			printf("%s\n", hashtext);
			return 0;
		}
		else
		{
			printf("scrypt error\n");
			return 1;
		}
	}
	else
	{
		printf("Read error\n");
	}
	return 1;
}
