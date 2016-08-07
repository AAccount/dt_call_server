#JAVA1BYTE: workaround for java sending the first byte over a socket separately on the second and subsequent writes
#JCALLDIAG: show the call contents as text for jclient. won't show anything meaningful in a real call
#JSTOPMEDIA: for removeClient, only remove both command and media if the given socket descriptor was a command. currently media is being killed and restarted by jclient to stop the 2 media r/w threads. you don't want to be kicked out by having the command socket closed because you're using THE ONLY known workaround for stopping a blocking thread in java
#VERBOSE: print out a summary of what happened every single select call. (the old cout, pre dblog, debugging output)
MATH = -lm
OPENSSL = -lssl -lcrypto
PQXX =  -lpqxx -lpq

UNAME=$(shell uname -s)
ifeq ($(UNAME),Linux)
 CFLAGS = -O3 -march=native -Werror -std=c++11 -DJAVA1BYTE -DJSTOPMEDIA
 DBGFLAGS = -g -Werror -std=c++11 -DJAVA1BYTE -DJSTOPMEDIA -DJCALLDIAG
 CC = g++
endif
ifeq ($(UNAME),FreeBSD)
 CFLAGS = -O3 -march=native -Werror -DJAVA1BYTE -DJSTOPMEDIA
 DBGFLAGS = -g -Werror -DJAVA1BYTE -DJCALLDIAG -DJSTOPMEDIA -DJCALLDIAG
 INC = -I /usr/local/include
 LIB = -L /usr/local/lib
 CC = clang++
endif

server: server.o pgutils.o dblog.o
	${CC} -o dtoperator pgutils.o ${PQXX} server.o dblog.o ${OPENSSL} ${MATH} ${INC} ${LIB}

testdb: testdb.cpp pgutils.o
	${CC} ${CFLAGS} -o $@ testdb.cpp pgutils.o ${PQXX} ${INC} ${LIB}

pgutils.o : pgutils.cpp pgutils.hpp
	${CC} ${CFLAGS} -c pgutils.cpp ${INC}

server.o : server.cpp server.hpp
	${CC} ${CFLAGS} -c server.cpp ${INC}

dblog.o: dblog.cpp dblog.hpp
	${CC} ${CFLAGS} -c dblog.cpp ${INC}

clean:
	rm client dtoperator testdb *.o *.gch

