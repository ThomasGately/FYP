//central_server.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <sstream>
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
#include <queue> 
#include <vector>
#include <thread>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>

using namespace std;
#define stringify(name) # name
#define DEBUG 0
#define FAIL -1

string current_dir;

int send_message(int port, std::string hostname, std::string message);
string get_current_dir();
inline string get_current_date_time(string s);
inline void logger(const char *fmt, ...);
inline void openssl_logger();
string send_build_files_to_central (int server_no, struct testing_server servers, string path_to_file, string path_to_destination);
string send_build_files_to_test_server(int server_no, struct testing_server servers, string path_to_file, string path_to_destination);

struct testing_server;

enum tasks {
    task_exec_cmd, 
    task_git_clone,
    task_git_checkout,
    task_run_test,
    task_build_project,
    task_un_zip_build,
    task_run_bash_script
};

string tasks_names[] {
    stringify(task_exec_cmd), 
    stringify(task_git_clone),
    stringify(task_git_checkout),
    stringify(task_run_test),
    stringify(task_build_project),
    stringify(task_un_zip_build),
    stringify(task_run_bash_script)
};

string get_current_dir() {

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {

        logger("get_current_dir() error");
    }
    return string(cwd);
}

inline string get_current_date_time(string s) {

    time_t now = time(0);
    struct tm  tstruct;
    char  buf[80];
    tstruct = *localtime(&now);
    if (s == "now") {
        strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    }
    else if (s == "date"){
        strftime(buf, sizeof(buf), "%Y-%m-%d", &tstruct);
    }
    return string(buf);
};

inline void logger(const char *fmt, ...) {

    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    string filePath = current_dir + "/logs/log_central_server_" + get_current_date_time("date") + ".log";
    string now = get_current_date_time("now");
    ofstream ofst;
    ofst.open(filePath.c_str(), std::ios_base::out | std::ios_base::app );

    if (!ofst) {
        ofst.open(filePath.c_str(), fstream::out | fstream::trunc);
    }

    if (DEBUG) {
        cout << now << '\t' << buffer << '\n';
    }

    ofst << now << '\t' << buffer << '\n';
    ofst.close();
}

inline void error_logger(const char *fmt, ...) {

    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    string filePath = current_dir + "/logs/log_central_server_" + get_current_date_time("date") + ".log";
    string now = get_current_date_time("now");
    ofstream ofst;
    ofst.open(filePath.c_str(), std::ios_base::out | std::ios_base::app );

    if (!ofst) {
        ofst.open(filePath.c_str(), fstream::out | fstream::trunc);
    }

    cout << now << '\t' << buffer << '\n';
    ofst << now << '\t' << buffer << '\n';
    ofst.close();
}

inline void openssl_logger() {

    FILE* file;
    string filePath = current_dir + "/logs/log_" + get_current_date_time("date") + ".log";
    file = fopen(filePath.c_str(), "a");

    if (DEBUG) {
        ERR_print_errors_fp(stderr);
    }
    else {
        ERR_print_errors_fp(file);
    }
}

int OpenConnection(const char *hostname, int port)
{   int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	if ( (host = gethostbyname(hostname)) == NULL )
	{
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(sd);
		perror(hostname);
		abort();
	}
	return sd;
}

SSL_CTX* InitCTX(void) {

	const SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = TLS_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	if ( cert != NULL )
	{
		logger("Server certificates:");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		logger("Subject: %s", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		logger("Issuer: %s", line);
		free(line);       /* free the malloc'ed string */
		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		logger("Info: No client certificates configured.");
}

int temp(int count, char *strings[]) {

	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
	int bytes;
	char *hostname, *portnum;

	if ( count != 3 )
	{
		logger("usage: %s <hostname> <portnum>\n", strings[0]);
		exit(0);
	}
	SSL_library_init();
	hostname=strings[1];
	portnum=strings[2];

	ctx = InitCTX();
	server = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);      /* create new SSL connection state */
	SSL_set_fd(ssl, server);    /* attach the socket descriptor */
	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
		ERR_print_errors_fp(stderr);
	else
	{   
		ShowCerts(ssl);        /* get any certs */
		char *msg = "Hello???";

		logger("Connected with %s encryption\n", SSL_get_cipher(ssl));
		SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
		buf[bytes] = 0;
		logger("Received: \"%s\"\n", buf);
		SSL_free(ssl);        /* release connection state */
	}
	close(server);         /* close socket */
	SSL_CTX_free(ctx);        /* release context */
	return 0;

}

struct testing_server {

	int no_of_servers = 0;
	vector<int> port;
	vector<int> in_use;
	vector<string> name;
	vector<string> hostname;
	vector<string> username;

	void setup_testing_server() {

		/*
	serialized(7000, "192.168.1.32", "0 ls -la");
	serialized(7001, "192.168.1.30", "0 ls -la");
	serialized(7002, "192.168.1.33", "0 ls -la");
	serialized(7006, "192.168.1.34", "0 ls -la");
		*/

		port.push_back(9004);
		in_use.push_back(0);
		name.push_back("ubuntu RPI 1");
		hostname.push_back("192.168.1.30");
		username.push_back("ubuntu");
		
		port.push_back(9001);
		in_use.push_back(0);
		name.push_back("ubuntu RPI 2");
		hostname.push_back("192.168.1.34");
		username.push_back("ubuntu");

		port.push_back(9002);
		in_use.push_back(0);
		name.push_back("ubuntu RPI 3");
		hostname.push_back("192.168.1.33");
		username.push_back("ubuntu");

		port.push_back(9003);
		in_use.push_back(0);
		name.push_back("ubuntu RPI 4");
		hostname.push_back("192.168.1.32");
		username.push_back("ubuntu");

		no_of_servers = 4;


		/*

		hostname.push_back("172.17.0.1");
		hostname.push_back("172.17.0.1");
		hostname.push_back("172.17.0.1");
		hostname.push_back("172.17.0.1");

		*/		
	}

	void setup_testing_server_localhost() {

		port.push_back(6969);
		in_use.push_back(false);
		name.push_back("my pc");
		hostname.push_back("192.168.1.21");
		username.push_back("tom");

		++no_of_servers;
	}
};

int send_message(int port, std::string hostname, std::string message) {

	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
	int bytes;

	SSL_library_init();


	logger("%s --- %d -- %s\n", hostname.c_str(), port, message.c_str());

	ctx = InitCTX();
	server = OpenConnection(hostname.c_str(), port);

	//create new SSL connection state 
	ssl = SSL_new(ctx);

	//attach the socket descriptor
	SSL_set_fd(ssl, server);

	//perform the connection
	if (SSL_connect(ssl) == FAIL) {
		ERR_print_errors_fp(stderr);
	}
	else {
		logger("Connected with %s encryption\n", SSL_get_cipher(ssl));
		//encrypt & send message
		SSL_write(ssl, message.c_str(), strlen(message.c_str()));
		//get reply & decrypt
		bytes = SSL_read(ssl, buf, sizeof(buf));
		buf[bytes] = 0;
		logger("Received: \"%s\"\n", buf);
		//release connection state
		SSL_free(ssl);
	}
	//close socket
	close(server);
	//release context
	SSL_CTX_free(ctx);
	return 0;

}


	static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
	static CRYPTO_RWLOCK *wr_lock;
	static CRYPTO_RWLOCK *re_lock;


static void ossl_init_base(void) {

    wr_lock = CRYPTO_THREAD_lock_new();
		SSL_library_init();

}


static void myinit(void) {

	SSL_library_init();		
	wr_lock = CRYPTO_THREAD_lock_new();
	re_lock = CRYPTO_THREAD_lock_new();
}

static int my_wr_lock(void) {

	if (!CRYPTO_THREAD_run_once(&once, myinit) || wr_lock == NULL)
		return 0;

	return CRYPTO_THREAD_write_lock(wr_lock);
}

static int my_re_lock(void) {

	if (!CRYPTO_THREAD_run_once(&once, myinit) || re_lock == NULL)
		return 0;

	return CRYPTO_THREAD_read_lock(re_lock);
}

static int my_wr_unlock(void) {
	return CRYPTO_THREAD_unlock(wr_lock);
}


static int my_re_unlock(void) {
	return CRYPTO_THREAD_unlock(re_lock);
}

int serialized(int port, std::string hostname, tasks task, std::string message) {
	
	int ret = 0;

	std::stringstream ss;

	ss << task << " " << message;

	message = ss.str();

	logger("Serialized message to be sent --> %s", message.c_str());

	if (my_re_lock() && my_wr_lock()) {
		SSL_CTX *ctx;
		SSL *ssl;
		int server;
		char buf[1024];
		int bytes;

		ctx = InitCTX();

		server = OpenConnection(hostname.c_str(), port);

		//create new SSL connection state 
		ssl = SSL_new(ctx);
		//attach the socket descriptor
		SSL_set_fd(ssl, server);

		//perform the connection
		if (SSL_connect(ssl) == FAIL) {
			ERR_print_errors_fp(stderr);
		}
		else {
			logger("Connected with %s encryption", SSL_get_cipher(ssl));
			//encrypt & send message
			SSL_write(ssl, message.c_str(), strlen(message.c_str()));
			//get reply & decrypt
			bytes = SSL_read(ssl, buf, sizeof(buf));
			buf[bytes] = 0;

			if (string(buf).find("failure") != std::string::npos) {
				error_logger("failure --> \"%s\"", buf);
			}
			logger("Received: \"%s\"", buf);
			//release connection state
			SSL_free(ssl);
		}
		ERR_print_errors_fp(stderr);
		//close socket
		close(server);
		//release context
		SSL_CTX_free(ctx);
	}

	my_wr_unlock();
	my_re_unlock();
	return ret;
}

std::string exec_cmd(const char* cmd) {
	
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
    logger("Result:\n%s", result.c_str());
	return result;
}

void showq(std::queue<std::string> gq) 
{ 
	std::queue <std::string> g = gq; 
	while(!g.empty())  {

		std::cout << g.front() << '\n'; 
		g.pop(); 
	}
	send_message(6969, "172.17.0.1", "");
} 


void run_tests(int i, struct testing_server servers) {

	std::ifstream list_of_tests("project/list_of_tests");
	std::queue<std::string> tests;
	std::string line;

	while (list_of_tests >> line) {
		tests.push(line);
	}

	//send_message(6969, "172.17.0.1", "0 bash project/make.sh 100");

	while(!tests.empty()) {

		std::stringstream ss;
		ss << tests.front() << " 1 1";
		serialized(servers.port[i], servers.hostname[i], task_run_test, ss.str());
		tests.pop(); 
	}
}

void run_tests_thread(vector<int> server_nos, struct testing_server servers) {

	std::ifstream list_of_tests("project/list_of_tests");
	std::queue<std::string> tests;
	std::string line;

	for (int i = 0; i < server_nos.size(); ++i) {

		//send_build_files_to_test_server(server_nos[i], servers, current_dir + "/project/ziptest.zip", "/home/ubuntu/FYP/project/ziptest.zip");
	}

	while (list_of_tests >> line) {
		tests.push(line);
	}

	//send_message(6969, "172.17.0.1", "0 bash project/make.sh 100");

	while(!tests.empty()) {

		std::vector<std::thread> thread_servers;
		std::stringstream ss;

		for(int i = 0; i < server_nos.size(); ++i) {

			ss << tests.front() << " 1 2";
			thread_servers.push_back(std::thread(serialized, servers.port[server_nos[i]], servers.hostname[server_nos[i]], task_run_test, ss.str()));
			tests.pop();
			ss.str(std::string());
		}

		for(auto& t : thread_servers) {
            t.join();
		}
        thread_servers.clear();
	}
}

string send_build_files_to_test_server(int server_no, struct testing_server servers, string path_to_file, string path_to_destination) {

	logger("send_build_files_to_central\n path_to_file --> %s\n path_to_destination --> %s", path_to_file.c_str(), path_to_destination.c_str());

	stringstream ss;

	//sshpass -p "kekman69" scp binary.zip ubuntu@192.168.1.34:/home/ubuntu/testing 
	ss << "scp " << path_to_file << ' ' << servers.username[server_no] << '@' << servers.hostname[server_no] << ':' << path_to_destination;

	logger("send_build_files_to_central --> %s", ss.str().c_str());

	serialized(servers.port[server_no], servers.hostname[server_no], task_un_zip_build, "task_un_zip_build");

	return exec_cmd(ss.str().c_str());
}


string send_build_files_to_central(int server_no, struct testing_server servers, string path_to_file, string path_to_destination) {

	logger("send_build_files_to_central\n path_to_file --> %s\n path_to_destination --> %s", path_to_file.c_str(), path_to_destination.c_str());

	stringstream ss;

	//sshpass -p "kekman69" scp binary.zip ubuntu@192.168.1.34:/home/ubuntu/testing 
	ss << "scp " << servers.username[server_no] << '@' << servers.hostname[server_no] << ':' << path_to_file << ' ' << path_to_destination;

	logger("send_build_files_to_central --> %s", ss.str().c_str());

	serialized(servers.port[server_no], servers.hostname[server_no], task_un_zip_build, "task_un_zip_build");

	return exec_cmd(ss.str().c_str());
}


int find_free_server(struct testing_server &servers) {

	int count = 0;

	while (true) {

        if (servers.in_use[count] == 0) {
        	servers.in_use[count] = 1;
        	return count;
        }
        if(servers.no_of_servers - 1 == count){
        	count = 0;
        }
        else {
        	++count;
        }
	}
}

vector<int> find_multiple_free_server(int no_of_servers, struct testing_server servers) {

	vector<int> found_severs;

	for (int i = 0; i < no_of_servers; ++i) {

		int temp = find_free_server(servers);
		found_severs.push_back(temp);
		logger("test%d", found_severs[i]);
		logger("find_free_server --> %s", servers.hostname[found_severs[i]].c_str());
		
	}
	return found_severs;
}

void build_project(int server_no, struct testing_server servers) {

	serialized(servers.port[server_no], servers.hostname[server_no], task_run_bash_script, "clean.sh");

	serialized(servers.port[server_no], servers.hostname[server_no], task_build_project, "make.sh 100");
}

void test_on_localhost() {

    current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server_localhost();

	int server_no = find_free_server(servers);

	build_project(server_no, servers);

	exec_cmd("rm /project/build/testxx*");

	send_build_files_to_central(0, servers, current_dir + "/project/ziptest.zip", current_dir + "/project/ziptest.zip");

	run_tests(0, servers);
}

void test_on_pis() {

    current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server();

	int server_no = find_free_server(servers);

	build_project(server_no, servers);

	//send_build_files_to_central(server_no, servers, "/home/ubuntu/FYP/project/ziptest.zip", current_dir + "/project/ziptest.zip");

	servers.in_use[server_no] = false;

	vector<int> server_nos = find_multiple_free_server(1, servers);

	run_tests_thread(server_nos, servers);
}

void test_on_pi() {

    current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server();

	int server_no = find_free_server(servers);

	build_project(server_no, servers);

	send_build_files_to_central(server_no, servers, current_dir + "/project/ziptest.zip", current_dir + "/project/ziptest.zip");

	run_tests(server_no, servers);
}

#include <benchmark/benchmark.h>

static void BM_build_project(benchmark::State& state) {

    current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server();

	int server_no = find_free_server(servers);

  	for (auto _ : state){
    	build_project(server_no, servers);
  	}
}

static void BM_test_on_pi(benchmark::State& state) {

    current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server();

	int server_no = find_free_server(servers);

	//build_project(server_no, servers);

	send_build_files_to_central(server_no, servers, current_dir + "/project/ziptest.zip", current_dir + "/project/ziptest.zip");

  	for (auto _ : state){
    	run_tests(server_no, servers);
  	}
}

static void BM_test_on_4_pis(benchmark::State& state) {

    current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server();

	int server_no = find_free_server(servers);

	//build_project(server_no, servers);

	//send_build_files_to_central(server_no, servers, "/home/ubuntu/FYP/project/ziptest.zip", current_dir + "/project/ziptest.zip");

	servers.in_use[server_no] = false;

	vector<int> server_nos = find_multiple_free_server(4, servers);
	
	for (auto _ : state) {
    	run_tests_thread(server_nos, servers);
	}

}

//BENCHMARK(BM_build_project);
BENCHMARK(BM_test_on_pi);
BENCHMARK(BM_test_on_4_pis);

BENCHMARK_MAIN();

/*
int main(int count, char *strings[]) {

	//test_on_pis();
}
*/