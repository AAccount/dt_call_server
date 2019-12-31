#VERBOSE: print out a summary of what happened every single select call. (the old cout, pre dblog, debugging output)
MATH = -lm
PTHREAD = -pthread
SODIUM = -lsodium

UNAME = $(shell uname -s)
ifeq ($(UNAME),Linux)
	ifeq ($(shell uname -p),ppc64le)
		#Only alternate arch ever tested with dtoperator courtesy of my Raptor Blackbird
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

ifeq ($(UNAME), $(filter $(UNAME), FreeBSD OpenBSD))
	OPTCFLAGS = -O2 -march=native -Werror -fPIE
	CFLAGS = -g -Werror -fPIE
	LDFLAGS = -pie
	INC = -I /usr/local/include
	LIB = -L /usr/local/lib
	CXX = clang++ -std=c++14
endif

OBJS = server.o server_init.o UserUtils.o Log.o ServerUtils.o User.o const.o Client.o sodium_utils.o stringify.o Logger.o
TARGET = dtoperator

all: ${OBJS}
	${CXX} ${CFLAGS} ${LDFLAGS} -o ${TARGET} ${OBJS} ${MATH} ${PTHREAD} ${SODIUM} ${INC} ${LIB}

server.o : src/server.cpp src/server.hpp
	${CXX} ${CFLAGS} -c src/server.cpp ${INC}
	
server_init.o : src/server_init.cpp src/server_init.hpp
	${CXX} ${CFLAGS} -c src/server_init.cpp ${INC}

sodium_utils.o : src/sodium_utils.cpp src/sodium_utils.hpp
	${CXX} ${CFLAGS} -c src/sodium_utils.cpp ${INC}

stringify.o : src/stringify.cpp src/stringify.hpp
	${CXX} ${CFLAGS} -c src/stringify.cpp ${INC}

UserUtils.o : src/UserUtils.cpp src/UserUtils.hpp
	${CXX} ${CFLAGS} -c src/UserUtils.cpp ${INC}
	
Log.o : src/Log.cpp src/Log.hpp
	${CXX} ${CFLAGS} -c src/Log.cpp ${INC}
	
ServerUtils.o : src/ServerUtils.cpp src/ServerUtils.hpp
	${CXX} ${CFLAGS} -c src/ServerUtils.cpp ${INC}
	
User.o : src/User.cpp src/User.hpp
	${CXX} ${CFLAGS} -c src/User.cpp ${INC}

const.o : src/const.cpp src/const.h
	${CXX} ${CFLAGS} -c src/const.cpp ${INC}

Logger.o : src/Logger.cpp src/Logger.hpp src/BlockingQ.hpp
	${CXX} ${CFLAGS} -c src/Logger.cpp ${INC}
	
Client.o : src/Client.cpp src/Client.hpp
	${CXX} ${CFLAGS} -c src/Client.cpp ${INC}

keygen: src/keygen.cpp Utils.o src/keygen.hpp const.o
	${CXX} ${CFLAGS} ${LDFLAGS} ${SODIUM} -o keygen src/keygen.cpp src/Utils.cpp src/const.cpp src/stringify.cpp src/sodium_utils.cpp ${INC} ${LIB}
	
clean:
	rm dtoperator *.o keygen

