#JAVA1BYTE: workaround for java sending the first byte over a socket separately on the second and subsequent writes
#JCALLDIAG: show the call contents as text for jclient. won't show anything meaningful in a real call
#JSTOPMEDIA: for removeClient, only remove both command and media if the given socket descriptor was a command. currently media is being killed and restarted by jclient to stop the 2 media r/w threads. you don't want to be kicked out by having the command socket closed because you're using THE ONLY known workaround for stopping a blocking thread in java
#MEMCHECK: respond to the "suicide" command which causes the server to shutdown. useful for checking memory leaks
MATH = -lm
OPENSSL = -lssl -lcrypto
PQXX =  -lpqxx -lpq

UNAME=$(shell uname -s)
ifeq ($(UNAME),Linux)
 OPTFLAGS = -O3 -march=native -Werror -std=c++11 -DJAVA1BYTE -DJSTOPMEDIA
 CFLAGS = -g -Werror -std=c++11 -DJAVA1BYTE -DJSTOPMEDIA
 CC = g++
endif
ifeq ($(UNAME),FreeBSD)
 OPTFLAGS = -O3 -march=native -Werror -DJAVA1BYTE -DJSTOPMEDIA
 CFLAGS = -g -Werror -DJAVA1BYTE -DJCALLDIAG -DJSTOPMEDIA
 INC = -I /usr/local/include
 LIB = -L /usr/local/lib
 CC = clang++
endif

server: server.o pgutils.o
	${CC} -o $@ pgutils.o ${PQXX} server.o ${OPENSSL} ${MATH} ${INC} ${LIB}

testdb: testdb.cpp pgutils.o
	${CC} ${CFLAGS} -o $@ testdb.cpp pgutils.o ${PQXX} ${INC} ${LIB}

pgutils.o : pgutils.cpp pgutils.hpp
	${CC} ${CFLAGS} -c pgutils.cpp ${INC}

server.o : server.cpp server.hpp
	${CC} ${CFLAGS} -c server.cpp ${INC}

clean:
	rm client server testdb *.o *.gch

