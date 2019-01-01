#JCALLDIAG: show the call contents as text for jclient. won't show anything meaningful in a real call
#VERBOSE: print out a summary of what happened every single select call. (the old cout, pre dblog, debugging output)
MATH = -lm
PTHREAD = -pthread
SODIUM = -lsodium

SHARED = -shared -fPIC
SELF_LOCATION = -L.
SELF_SODIUM = -lsodiumutils
SELF_STRINGIFY = -lstringify
SELF_LOGGER = -llogger

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
 CXX = clang++ -std=c++14
endif

OBJS = server.o server_init.o UserUtils.o Log.o Utils.o User.o const.o Client.o
SELF_LIBS = libsodiumutils.so libstringify.so liblogger.so
TARGET = dtoperator

all: ${OBJS} ${SELF_LIBS}
	${CXX} ${CFLAGS} ${LDFLAGS} -o ${TARGET} ${OBJS} ${SELF_LOCATION} ${SELF_SODIUM} ${SELF_STRINGIFY} ${SELF_LOGGER} ${MATH} ${PTHREAD} ${SODIUM} ${INC} ${LIB}

server.o : server.cpp server.hpp
	${CXX} ${CFLAGS} -c server.cpp ${INC}
	
server_init.o : server_init.cpp server_init.hpp
	${CXX} ${CFLAGS} -c server_init.cpp ${INC}

libsodiumutils.so : sodium_utils.cpp sodium_utils.hpp
	${CXX} ${CFLAGS} ${SHARED} -o ${@} sodium_utils.cpp ${INC} ${SODIUM}

libstringify.so : stringify.cpp stringify.hpp
	${CXX} ${CFLAGS} ${SHARED} -o ${@} stringify.cpp ${INC}

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

liblogger.so : Logger.cpp Logger.hpp
	${CXX} ${CFLAGS} ${SHARED} -o ${@} Logger.cpp ${INC}
	
Client.o : Client.cpp Client.hpp
	${CXX} ${CFLAGS} -c Client.cpp ${INC}

keygen: keygen.cpp Utils.o keygen.hpp const.o
	${CXX} ${CFLAGS} ${LDFLAGS} ${SODIUM} -o keygen keygen.cpp Utils.o const.o sodium_utils.o stringify.o ${INC} ${LIB}
	
clean:
	rm dtoperator *.o keygen *.so

