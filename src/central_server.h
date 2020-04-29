#ifndef CENTRAL_SERVER_H
#define CENTRAL_SERVER_H
//central_server.h

#include "str_testing_server.h"
#include "tasks.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <sstream>
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <queue> 
#include <vector>
#include <thread>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>

using namespace std;

class central_server {

public:
	static void test_on_localhost();
	static void test_on_pi();
	static void test_on_pis();

private:
	static int send_message(int port, string hostname, tasks::enum_tasks task, string message);
	static int send_message_sockaddr(int port, string hostname, tasks::enum_tasks task, string message);
	static int send_message_openssl(int port, std::string hostname, tasks::enum_tasks task, std::string message);
	static int open_connection(const char *hostname, int port);
	static SSL_CTX* init_CTX(void);
	static void show_certs(SSL* ssl);
	static void my_init(void);
	static int my_wr_lock(void);
	static int my_re_lock(void);
	static int my_wr_unlock(void);
	static int my_re_unlock(void);void show_queue(std::queue<std::string> input_queue);
	static void run_tests(int i, struct str_testing_server servers);
	static void run_tests_thread(vector<int> server_nos, struct str_testing_server servers);
	static string send_build_files_to_test_server(int server_no, struct str_testing_server servers, string path_to_file, string path_to_destination);
	static string send_build_files_to_central(int server_no, struct str_testing_server servers, string path_to_file, string path_to_destination);
	static int find_free_server(struct str_testing_server &servers);
	static vector<int> find_multiple_free_server(int no_of_servers, struct str_testing_server servers);
	static void build_project(int server_no, struct str_testing_server servers);
};

#endif