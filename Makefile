#JAVA1BYTE: workaround for java sending the first byte over a socket separately on the second and subsequent writes
#JCALLDIAG: show the call contents as text for jclient. won't show anything meaningful in a real call
#JSTOPMEDIA: for removeClient, only remove both command and media if the given socket descriptor was a command. currently media is being killed and restarted by jclient to stop the 2 media r/w threads. you don't want to be kicked out by having the command socket closed because you're using THE ONLY known workaround for stopping a blocking thread in java
#VERBOSE: print out a summary of what happened every single select call. (the old cout, pre dblog, debugging output)
MATH = -lm
OPENSSL = -lssl -lcrypto
SCRYPT = -lscrypt
PTHREAD = -pthread

UNAME = $(shell uname -s)
ifeq ($(UNAME),Linux)
 LEGACYDBGCFLAGS = -g -m32 -Werror -DJSTOPMEDIA -fPIE
 OPTCFLAGS = -flto -O3 -march=native -Werror -DJSTOPMEDIA -fPIE -D_FORTIFY_SOURCE=2
 CFLAGS = -g -Werror -DJSTOPMEDIA -DJCALLDIAG -fPIE
 LDFLAGS = -pie
 CC = gcc
 CXX = g++ -std=c++11
endif

ifeq ($(UNAME),FreeBSD)
 CFLAGS = -O3 -march=native -Werror -DJSTOPMEDIA -fPIE
 DBGFLAGS = -g -Werror -DJCALLDIAG -DJSTOPMEDIA -DJCALLDIAG -fPIE
 LDFLAGS = -pie
 INC = -I /usr/local/include
 LIB = -L /usr/local/lib
 CC = clang
 CXX = clang++ -std=c++11
endif

server: server.o server_init.o UserUtils.o Log.o Utils.o User.o
	${CXX} ${CFLAGS} ${LDFLAGS} -o dtoperator server.o server_init.o UserUtils.o Log.o Utils.o User.o ${SCRYPT} ${OPENSSL} ${MATH} ${PTHREAD} ${INC} ${LIB}

server.o : server.cpp server.hpp
	${CXX} ${CFLAGS} -c server.cpp ${INC}
	
server_init.o : server_init.cpp server_init.hpp
	${CXX} ${CFLAGS} -c server_init.cpp ${INC}
	
UserUtils.o : UserUtils.cpp UserUtils.hpp
	${CXX} ${CFLAGS} -c UserUtils.cpp ${INC}
	
Log.o : Log.cpp Log.hpp
	${CXX} ${CFLAGS} -c Log.cpp ${INC}
	
Utils.o : Utils.cpp Utils.hpp
	${CXX} ${CFLAGS} -c Utils.cpp ${INC}
	
User.o : User.cpp User.hpp
	${CXX} ${CFLAGS} -c User.cpp ${INC}

clean:
	rm dtoperator *.o

