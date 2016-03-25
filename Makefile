#JAVA1BYTE: workaround for java sending the first byte over a socket separately on the second and subsequent writes
#JCALLDIAG: show the call contents as text for jclient. won't show anything meaningful in a real call
#JSTOPMEDIA: for removeClient, only remove both command and media if the given socket descriptor was a command. currently media is being killed and restarted by jclient to stop the 2 media r/w threads. you don't want to be kicked out by having the command socket closed because you're using THE ONLY known workaround for stopping a blocking thread in java
#MEMCHECK: respond to the "suicide" command which causes the server to shutdown. useful for checking memory leaks

OPTFLAGS = -O3 -march=native -Werror -std=c++11 -DJAVA1BYTE -DJSTOPMEDIA
CFLAGS = -g -Werror -std=c++11 -DJAVA1BYTE -DJCALLDIAG -DJSTOPMEDIA

MATH = -lm
OPENSSL = -lssl -lcrypto
PQXX =  -lpqxx -lpq

server: server.o pgutils.o
	g++ -o $@ pgutils.o ${PQXX} server.o ${OPENSSL} ${MATH}

testdb: testdb.cpp pgutils.o
	g++ ${CFLAGS} -o $@ testdb.cpp pgutils.o ${PQXX}

pgutils.o : pgutils.cpp pgutils.hpp
	g++ ${CFLAGS} -c pgutils.cpp pgutils.hpp ${PQXX}

server.o : server.cpp server.hpp
	g++ ${CFLAGS} -c server.cpp server.hpp const.h ${OPENSSL} ${MATH}

clean:
	rm client server testdb *.o *.gch

