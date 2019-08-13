#VERBOSE: print out a summary of what happened every single select call. (the old cout, pre dblog, debugging output)
MATH = -lm
PTHREAD = -pthread
SODIUM = -lsodium

UNAME = $(shell uname -s)
ifeq ($(UNAME),Linux)
	ifeq ($(shell uname -p),ppc64le)
		#Only alternate arch ever tested with dtoperator courtesy of a Raptor Blackbird
		NATIVECPU = -mcpu=native
	else
		#Assume x86(_64) unless otherwise
		NATIVECPU = -march=native
	endif
	OPTCFLAGS = -flto -O2 ${NATIVECPU} -Werror -fPIE -D_FORTIFY_SOURCE=2
	CFLAGS = -g -Werror -fPIE
	LDFLAGS = -pie
	CXX = g++ -std=c++14
endif

ifeq ($(UNAME),FreeBSD)
	OPTCFLAGS = -O2 -march=native -Werror -fPIE
	CFLAGS = -g -Werror -fPIE
	LDFLAGS = -pie
	INC = -I /usr/local/include
	LIB = -L /usr/local/lib
	CXX = clang++ -std=c++14
endif

OBJS = server.o server_init.o UserUtils.o Log.o Utils.o User.o const.o Client.o sodium_utils.o stringify.o Logger.o
TARGET = dtoperator

all: ${OBJS}
	${CXX} ${CFLAGS} ${LDFLAGS} -o ${TARGET} ${OBJS} ${MATH} ${PTHREAD} ${SODIUM} ${INC} ${LIB}

server.o : server.cpp server.hpp
	${CXX} ${CFLAGS} -c server.cpp ${INC}
	
server_init.o : server_init.cpp server_init.hpp
	${CXX} ${CFLAGS} -c server_init.cpp ${INC}

sodium_utils.o : sodium_utils.cpp sodium_utils.hpp
	${CXX} ${CFLAGS} -c sodium_utils.cpp ${INC}

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

Logger.o : Logger.cpp Logger.hpp BlockingQ.hpp
	${CXX} ${CFLAGS} -c Logger.cpp ${INC}
	
Client.o : Client.cpp Client.hpp
	${CXX} ${CFLAGS} -c Client.cpp ${INC}

keygen: keygen.cpp Utils.o keygen.hpp const.o
	${CXX} ${CFLAGS} ${LDFLAGS} ${SODIUM} -o keygen keygen.cpp Utils.cpp const.cpp stringify.cpp sodium_utils.cpp ${INC} ${LIB}
	
clean:
	rm dtoperator *.o keygen

