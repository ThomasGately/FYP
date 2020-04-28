
# Usage:
# make        # compile all binary
# make clean  # remove ALL binaries and objects

.PHONY = all clean

CC = gcc                        # compiler to use

all: test_server test central_server

test_server: src/test_server.cpp
	@echo "------ test_server.cpp ------\n"
	gcc -Wall -o build/test_server.out src/test_server.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -L/usr/local/lib/ -lZipper -lz

central_server: src/central_server.cpp
	@echo "------ central_server.cpp ------\n"
	gcc -Wall -o build/central_server.out src/central_server.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -pthread -L/usr/local/lib/ -lZipper -lz

bm_central_server: src/bm_central_server.cpp
	@echo "------ bm_central_server.cpp ------\n"
	g++ -Wall -o build/bm_central_server.out src/bm_central_server.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -ldl -pthread -L/usr/local/lib/ -lZipper -lz -std=c++11 -isystem benchmark/include -Lbenchmark/build/src -lbenchmark -lpthread

test: src/test.cpp
	@echo "------ test.cpp ------\n"
	gcc -Wall -o build/test.out src/test.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -pthread -L/usr/local/lib/ -lZipper -lz

openssl: src/openssl.cpp
	@echo "------ openssl.cpp ------\n"
	gcc -Wall -o build/openssl.out src/openssl.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -pthread

clean:
	@echo "Cleaning up..."
	rm -rvf build/client
	rm -rvf build/server
	rm -rvf build/test_server