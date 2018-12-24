#JCALLDIAG: show the call contents as text for jclient. won't show anything meaningful in a real call
#VERBOSE: print out a summary of what happened every single select call. (the old cout, pre dblog, debugging output)
MATH = -lm
PTHREAD = -pthread
SODIUM = -lsodium

UNAME = $(shell uname -s)
ifeq ($(UNAME),Linux)
 OPTCFLAGS = -flto -O2 -march=native -Werror -fPIE -D_FORTIFY_SOURCE=2
 CFLAGS = -g -Werror -fPIE
 LDFLAGS = -pie
 CXX = g++ -std=c++14
endif

ifeq ($(UNAME),FreeBSD)
 CFLAGS = -O2 -march=native -Werror -fPIE
 DBGFLAGS = -g -Werror -fPIE
 LDFLAGS = -pie
 INC = -I /usr/local/include
 LIB = -L /usr/local/lib
 CXX = clang++ -std=c++11
endif

server: server.o server_init.o UserUtils.o Log.o Utils.o User.o const.o Logger.o sodium_utils.o stringify.o Client.o
	${CXX} ${CFLAGS} ${LDFLAGS} -o dtoperator server.o server_init.o UserUtils.o Log.o Utils.o User.o const.o Logger.o Client.o sodium_utils.o stringify.o ${SELF_LIBS} ${SELF_SODIUM} ${SELF_STRINGIFY} ${MATH} ${PTHREAD} ${SODIUM} ${INC} ${LIB}

server.o : server.cpp server.hpp
	${CXX} ${CFLAGS} -c server.cpp ${INC}
	
server_init.o : server_init.cpp server_init.hpp
	${CXX} ${CFLAGS} -c server_init.cpp ${INC}

sodium_utils.o : sodium_utils.cpp sodium_utils.hpp
	${CXX} ${CFLAGS} -c sodium_utils.cpp ${INC} ${SODIUM}

stringify.o : stringify.cpp stringify.hpp
	${CXX} ${CFLAGS} -c stringify.cpp ${INC}

UserUtils.o : UserUtils.cpp UserUtils.hpp
	${CXX} ${CFLAGS} -c UserUtils.cpp ${INC}
	
Log.o : Log.cpp Log.hpp
	${CXX} ${CFLAGS} -c Log.cpp ${INC}
	
Utils.o : Utils.cpp Utils.hpp
	${CXX} ${CFLAGS} -c Utils.cpp ${INC}
	
User.o : User.cpp User.hpp
	${CXX} ${CFLAGS} -c User.cpp ${INC}

const.o : const.cpp const.h
	${CXX} ${CFLAGS} -c const.cpp ${INC}

Logger.o : Logger.cpp Logger.hpp
	${CXX} ${CFLAGS} -c Logger.cpp ${INC}
	
Client.o : Client.cpp Client.hpp
	${CXX} ${CFLAGS} -c Client.cpp ${INC}

keygen: keygen.cpp Utils.o keygen.hpp const.o
	${CXX} ${CFLAGS} ${LDFLAGS} ${SODIUM} -o keygen keygen.cpp Utils.o const.o ${INC} ${LIB}
	
clean:
	rm dtoperator *.o keygen *.so

