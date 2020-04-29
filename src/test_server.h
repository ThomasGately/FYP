#ifndef TEST_SERVER_H
#define TEST_SERVER_H
//test_server.h

#include "str_testing_server.h"
#include "tasks.h"

#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <fstream>
#include <string>
#include <sstream>

using namespace std;

static string hostname;

class test_server {

public:
	static void run_openssl(int port);
	static void run_sockaddr(int port);
	static void run(int port, string _hostname);

private:
	static int open_listener(int port);
	static int is_root(void);
	static SSL_CTX* init_server_CTX(void);
	static void load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
	static void show_certs(SSL* ssl);
	static void servlet(SSL* ssl);
};

#endif