#VERBOSE: print out a summary of what happened every single select call. (the old cout, pre dblog, debugging output)
MATH = -lm
PTHREAD = -pthread
SODIUM = -lsodium

UNAME = $(shell uname -s)
ifeq ($(UNAME),Linux)
	ifeq ($(shell uname -p),ppc64le)
		NATIVECPU = -mcpu=native
	else
		NATIVECPU = -march=native
	endif
	OPTCFLAGS = -flto -O2 ${NATIVECPU} -Werror -fPIE -D_FORTIFY_SOURCE=2
	CFLAGS = -g -Werror -fPIE
	LDFLAGS = -pie
	CXX = g++ -std=c++17
endif

ifeq ($(UNAME), $(filter $(UNAME), FreeBSD OpenBSD))
	OPTCFLAGS = -O2 -march=native -Werror -fPIE
	CFLAGS = -g -Werror -fPIE
	LDFLAGS = -pie
	INC = -I /usr/local/include
	LIB = -L /usr/local/lib
	CXX = clang++ -std=c++17
endif

OBJS = server.o server_init.o UserUtils.o Log.o ServerUtils.o User.o Client.o sodium_utils.o stringify.o Logger.o CommandUtils.o CommandContext.o ServerCommands.o UdpContext.o UdpCommand.o
TARGET = dtoperator

all: ${OBJS}
	${CXX} ${CFLAGS} ${LDFLAGS} -o ${TARGET} ${OBJS} ${MATH} ${PTHREAD} ${SODIUM} ${INC} ${LIB}

Log.o : src/Log/Log.cpp src/Log/Log.hpp
	${CXX} ${CFLAGS} -c src/Log/Log.cpp ${INC}

Logger.o : src/Log/Logger.cpp src/Log/Logger.hpp src/Log/BlockingQ.hpp
	${CXX} ${CFLAGS} -c src/Log/Logger.cpp ${INC}

Client.o : src/User/Client.cpp src/User/Client.hpp
	${CXX} ${CFLAGS} -c src/User/Client.cpp ${INC}

User.o : src/User/User.cpp src/User/User.hpp src/const.h
	${CXX} ${CFLAGS} -c src/User/User.cpp ${INC}

UserUtils.o : src/User/UserUtils.cpp src/User/UserUtils.hpp src/User/User.hpp src/User/User.cpp src/Log/Log.hpp src/Log/Log.cpp src/Log/Logger.hpp src/Log/Logger.cpp src/ServerUtils.hpp src/ServerUtils.cpp src/const.h src/sodium_utils.hpp src/sodium_utils.cpp src/stringify.hpp src/stringify.cpp
	${CXX} ${CFLAGS} -c src/User/UserUtils.cpp ${INC}

CommandUtils.o: src/ServerCommand/CommandUtils.cpp src/ServerCommand/CommandUtils.hpp src/Log/Log.hpp src/Log/Log.cpp
	${CXX} ${CFLAGS} -c src/ServerCommand/CommandUtils.cpp ${INC}

CommandContext.o: src/ServerCommand/CommandContext.cpp src/ServerCommand/CommandContext.hpp src/User/Client.cpp src/User/Client.hpp src/User/UserUtils.hpp src/User/UserUtils.cpp src/Log/Logger.cpp src/Log/Logger.hpp
	${CXX} ${CFLAGS} -c src/ServerCommand/CommandContext.cpp ${INC}

ServerCommands.o: src/ServerCommand/ServerCommands.cpp src/ServerCommand/ServerCommands.hpp
	${CXX} ${CFLAGS} -c src/ServerCommand/ServerCommands.cpp ${INC}

UdpContext.o: src/ServerCommand/UdpContext.cpp src/ServerCommand/UdpContext.hpp
	${CXX} ${CFLAGS} -c src/ServerCommand/UdpContext.cpp ${INC}

UdpCommand.o: src/ServerCommand/UdpCommand.cpp src/ServerCommand/UdpCommand.hpp
	${CXX} ${CFLAGS} -c src/ServerCommand/UdpCommand.cpp ${INC}

server.o : src/server.cpp src/server.hpp
	${CXX} ${CFLAGS} -c src/server.cpp ${INC}
	
server_init.o : src/server_init.cpp src/server_init.hpp
	${CXX} ${CFLAGS} -c src/server_init.cpp ${INC}

sodium_utils.o : src/sodium_utils.cpp src/sodium_utils.hpp
	${CXX} ${CFLAGS} -c src/sodium_utils.cpp ${INC}

stringify.o : src/stringify.cpp src/stringify.hpp
	${CXX} ${CFLAGS} -c src/stringify.cpp ${INC}
	
ServerUtils.o : src/ServerUtils.cpp src/ServerUtils.hpp
	${CXX} ${CFLAGS} -c src/ServerUtils.cpp ${INC}
	
keygen: src/keygen.cpp ServerUtils.o src/keygen.hpp src/const.h
	${CXX} ${CFLAGS} ${LDFLAGS} ${SODIUM} -o keygen src/keygen.cpp src/ServerUtils.cpp src/stringify.cpp src/sodium_utils.cpp ${INC} ${LIB}
	
clean:
	rm dtoperator *.o keygen

