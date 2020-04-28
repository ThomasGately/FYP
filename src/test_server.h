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

string get_current_dir();
void zip_files();
void un_zip_files();
void chmod_tsets_files();
inline string get_current_date_time(string s);
inline void logger(const char *fmt, ...);
inline void openssl_logger();
int OpenListener(int port);
int isRoot();
SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);void Servlet(SSL* ssl);
void run(int count, char *strings[]);

#endif