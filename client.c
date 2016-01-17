#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "error.h"

using namespace std;
int main(int argc, char *argv[])
{
	int sockfd, portno, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	int returnValue;

	char buffer[256];
	if (argc < 3) 
	{
		fprintf(stderr,"usage %s hostname port\n", argv[0]);
		exit(0);
	}

	//ssl intialization
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	//setup server address and port
	portno = atoi(argv[2]);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	errorLT0(sockfd, "socket system call error");

	server = gethostbyname(argv[1]);
	errorEQ0((long long)server, "error getting server informatiton"); //TODO: 32bit ifdef for 32bit pointer

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);

	//ssl strcutures
	//DON'T VERIFY the server using a self signed cert
	SSL_CTX *sslcontext;
	SSL *sslconnection;
	sslcontext = SSL_CTX_new(TLSv1_method());
	SSL_CTX_set_options(sslcontext, SSL_OP_NO_TLSv1);
	SSL_CTX_set_options(sslcontext, SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_options(sslcontext, SSL_OP_SINGLE_DH_USE);
	
	//connect to the server
	returnValue = connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
	errorLT0(returnValue, "error connecting to the specified server");

	//make the socket ssl
	sslconnection = SSL_new(sslcontext);
	SSL_set_fd(sslconnection, sockfd);
	returnValue = SSL_connect(sslconnection);
	errorLT0(returnValue, "error establishing SSL connection");
	
	while(TRUE)
	{
		//write message to server
		printf("Please enter the message: ");
		bzero(buffer,256);
		fgets(buffer,255,stdin);
		string output = to_string((long)time(NULL)) + "|" + string(buffer);
		bzero(buffer, 256);
		memcpy(buffer, output.c_str(), output.size()-1); //don't send in new line from hitting enter
		n = SSL_write(sslconnection, buffer, strlen(buffer));

		errorLT0(n, "error writing to ssl socket");
		bzero(buffer,256);
		SSL_read(sslconnection, buffer, 255);
		cout << "received response: " << buffer << "\n";		
	}

/*
	//read response from server
	bzero(buffer,256);
	n = SSL_read(sslconnection, buffer, 255);
	errorLT0(n, "error reading from ssl socket");
	printf("%s\n",buffer);
	close(sockfd);
*/
	//shutdown openssl
	ERR_free_strings();
	EVP_cleanup();
	SSL_shutdown(sslconnection);
	SSL_free(sslconnection);

	return 0;
}
