
# Usage:
# make        # compile all binary
# make clean  # remove ALL binaries and objects

.PHONY = all clean

link = -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -L/usr/local/lib/ -lZipper -lz -pthread

CC = gcc                        # compiler to use

all: tasks str_testing_server central_server test_server main

tasks: src/tasks.cpp
	@echo "------ src/tasks.cpp ------\n"
	g++ -o build/tasks.o -c src/tasks.cpp $(link)

str_testing_server: src/str_testing_server.cpp
	@echo "------ str_testing_server.cpp ------\n"
	g++ -o build/str_testing_server.o -c src/str_testing_server.cpp $(link)

central_server: src/central_server.cpp
	@echo "------ central_server.cpp ------\n"
	g++ -o build/central_server.o -c src/central_server.cpp  $(link)

test_server: src/test_server.cpp
	@echo "------ test_server.cpp ------\n"
	g++ -o build/test_server.o -c src/test_server.cpp $(link)

main: src/main.cpp
	@echo "------ main.cpp ------\n"
	g++ -o build/main.out src/main.cpp build/tasks.o build/str_testing_server.o build/central_server.o build/test_server.o $(link)

bm_central_server: src/bm_central_server.cpp
	@echo "------ bm_central_server.cpp ------\n"
	g++ -o build/bm_central_server.out $(link) -std=c++11 -isystem benchmark/include -Lbenchmark/build/src -lbenchmark -lpthread

clean:
	@echo "Cleaning up..."
	rm -vf build/*.out
	rm -vf build/*.o

