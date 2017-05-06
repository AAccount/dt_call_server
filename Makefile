#JAVA1BYTE: workaround for java sending the first byte over a socket separately on the second and subsequent writes
#JCALLDIAG: show the call contents as text for jclient. won't show anything meaningful in a real call
#JSTOPMEDIA: for removeClient, only remove both command and media if the given socket descriptor was a command. currently media is being killed and restarted by jclient to stop the 2 media r/w threads. you don't want to be kicked out by having the command socket closed because you're using THE ONLY known workaround for stopping a blocking thread in java
#VERBOSE: print out a summary of what happened every single select call. (the old cout, pre dblog, debugging output)
MATH = -lm
OPENSSL = -lssl -lcrypto
SCRYPT = -lscrypt

UNAME = $(shell uname -s)
ifeq ($(UNAME),Linux)
 LEGACYDBGCFLAGS = -g -m32 -Werror -std=c++11 -DJSTOPMEDIA -fPIE -pie
 OPTCFLAGS = -flto -O3 -march=native -Werror -std=c++11 -DJSTOPMEDIA -fPIE -pie -D_FORTIFY_SOURCE=2
 CFLAGS = -g -Werror -std=c++11 -DJSTOPMEDIA -DJCALLDIAG -fPIE -pie
 CC = g++
endif

ifeq ($(UNAME),FreeBSD)
 CFLAGS = -O3 -march=native -Werror -DJSTOPMEDIA
 DBGFLAGS = -g -Werror -DJCALLDIAG -DJSTOPMEDIA -DJCALLDIAG
 INC = -I /usr/local/include
 LIB = -L /usr/local/lib
 CC = clang++
endif

server: server.o server_init.o UserUtils.o Log.o Utils.o User.o
	${CC} ${CFLAGS} -o dtoperator server.o server_init.o UserUtils.o Log.o Utils.o User.o ${SCRYPT} ${OPENSSL} ${MATH} ${INC} ${LIB}

server.o : server.cpp server.hpp
	${CC} ${CFLAGS} -c server.cpp ${INC}
	
server_init.o : server_init.cpp server_init.hpp
	${CC} ${CFLAGS} -c server_init.cpp ${INC}
	
UserUtils.o : UserUtils.cpp UserUtils.hpp
	${CC} ${CFLAGS} -c UserUtils.cpp ${INC}
	
Log.o : Log.cpp Log.hpp
	${CC} ${CFLAGS} -c Log.cpp ${INC}
	
Utils.o : Utils.cpp Utils.hpp
	${CC} ${CFLAGS} -c Utils.cpp ${INC}
	
User.o : User.cpp User.hpp
	${CC} ${CFLAGS} -c User.cpp ${INC}
	
genscrypt: genscrypt.c
	${CC} ${CFLAGS} -o $@ genscrypt.c ${SCRYPT} ${INC} ${LIB}

clean:
	rm dtoperator genscrypt *.o

