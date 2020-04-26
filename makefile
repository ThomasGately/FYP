
# Usage:
# make        # compile all binary
# make clean  # remove ALL binaries and objects

.PHONY = all clean

CC = gcc                        # compiler to use

all: test_server test openssl central_server

test_server: src/test_server.cpp
	@echo "------ test_server.cpp ------\n"
	gcc -Wall -o build/test_server.out src/test_server.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc

central_server: src/central_server.cpp
	@echo "------ central_server.cpp ------\n"
	gcc -Wall -o build/central_server.out src/central_server.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -pthread

test: src/test.cpp
	@echo "------ test.cpp ------\n"
	gcc -Wall -o build/test.out src/test.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -lzip -pthread

openssl: src/openssl.cpp
	@echo "------ openssl.cpp ------\n"
	gcc -Wall -o build/openssl.out src/openssl.cpp -L/usr/lib -lssl -lcrypto -xc++ -lstdc++ -shared-libgcc -lzip -pthread

clean:
	@echo "Cleaning up..."
	rm -rvf build/client
	rm -rvf build/server
	rm -rvf build/test_server