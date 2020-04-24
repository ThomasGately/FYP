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

int testtest = 0;

#define FAIL    -1


int send_message(int port, std::string hostname, std::string message);

//int send_message(int server, struct testing_server sever, std::string message);

struct testing_server;

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
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);       /* free the malloc'ed string */
		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		printf("Info: No client certificates configured.\n");
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
		printf("usage: %s <hostname> <portnum>\n", strings[0]);
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

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
		SSL_free(ssl);        /* release connection state */
	}
	close(server);         /* close socket */
	SSL_CTX_free(ctx);        /* release context */
	return 0;

}

struct testing_server {

	std::vector<int> port;
	std::vector<std::string> name;
	std::vector<std::string> hostname;
	std::vector<std::string> username;

	void setup_testing_server() {

		port.push_back(7000);
		port.push_back(7001);
		port.push_back(7002);
		port.push_back(7003);

		name.push_back("ubuntu RPI 1");
		name.push_back("ubuntu RPI 2");
		name.push_back("ubuntu RPI 3");
		name.push_back("ubuntu RPI 4");

		hostname.push_back("172.17.0.1");
		hostname.push_back("172.17.0.1");
		hostname.push_back("172.17.0.1");
		hostname.push_back("172.17.0.1");

		/*

		hostname.push_back("192.168.1.34");
		hostname.push_back("192.168.1.33");
		hostname.push_back("192.168.1.32");
		hostname.push_back("192.168.1.21");

		*/

		username.push_back("ubuntu");
		username.push_back("ubuntu");
		username.push_back("ubuntu");
		username.push_back("ubuntu");
	}

	std::string build_send_file_string(int server, std::string path_to_file, std::string path_to_destination) {

		std::stringstream ss;

		//sshpass -p "kekman69" scp binary.zip ubuntu@192.168.1.34:/home/ubuntu/testing 
		ss << "sshpass -p \"kekman69\" scp " << path_to_file << ' ' << username[server] << '@' << hostname[server] << ':' << path_to_destination;

		return ss.str();
	}
};

void test_printf() {

	printf("grim -- %d\n", testtest);

	testtest++;

}

int send_message(int port, std::string hostname, std::string message) {

	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
	int bytes;

		test_printf();


	SSL_library_init();

	test_printf();

	printf("%s --- %d -- %s\n", hostname.c_str(), port, message.c_str());

	ctx = InitCTX();
	server = OpenConnection(hostname.c_str(), port);
		test_printf();

	//create new SSL connection state 
	ssl = SSL_new(ctx);
		test_printf();

	//attach the socket descriptor
	SSL_set_fd(ssl, server);
		test_printf();

	//perform the connection
	if (SSL_connect(ssl) == FAIL) {
		ERR_print_errors_fp(stderr);
	}
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		//encrypt & send message
		SSL_write(ssl, message.c_str(), strlen(message.c_str()));
		//get reply & decrypt
		bytes = SSL_read(ssl, buf, sizeof(buf));
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
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

int serialized(int port, std::string hostname, std::string message) {
	
	int ret = 0;
		printf("%s --- %d -- %s\n", hostname.c_str(), port, message.c_str());


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
			printf("asdasd %d\n", 1);
		}
		else {
			printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
			//encrypt & send message
			SSL_write(ssl, message.c_str(), strlen(message.c_str()));
			//get reply & decrypt
			bytes = SSL_read(ssl, buf, sizeof(buf));
			buf[bytes] = 0;
			printf("Received: \"%s\"\n", buf);
			//release connection state
			SSL_free(ssl);
		}
		//close socket
		close(server);
		//release context
		SSL_CTX_free(ctx);
	}

	my_wr_unlock();
	my_re_unlock();
	return ret;
}

int serialized2(int port, std::string hostname, std::string message) {

	int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    char buffer[1024] = {0}; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(port); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, hostname.c_str(), &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    }
    printf("\ngrim \n"); 

    send(sock , message.c_str(), strlen(message.c_str()) , 0 ); 
    printf("\nkek 1\n"); 

    valread = read(sock , buffer, 1024); 
        printf("\nkek 2 \n"); 

    printf("%s\n", buffer); 
    return 0; 
}
/*
int send_message(int server, struct testing_server sever, std::string message) {

	return send_message(sever.port, sever.hostname[server], message);
}
*/
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
	printf("%s \n", result.c_str());
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


void run_tests() {

	std::ifstream list_of_tests("project/list_of_tests");
	std::queue<std::string> tests;
	std::string line;

	while (list_of_tests >> line) {
		tests.push(line);
	}

	//send_message(6969, "172.17.0.1", "0 bash project/make.sh 100");

	while(!tests.empty()) {

		std::stringstream ss;
		ss << "3 project/build/" << tests.front() << " 0.1 1";
		serialized2(6969, "172.17.0.1", ss.str());
		tests.pop(); 
	}
}

void run_tests_thread() {

	std::ifstream list_of_tests("project/list_of_tests");
	std::queue<std::string> tests;
	std::string line;

	testing_server servers;
	servers.setup_testing_server();

	while (list_of_tests >> line) {
		tests.push(line);
	}

	//send_message(6969, "172.17.0.1", "0 bash project/make.sh 100");

	while(!tests.empty()) {

		std::vector<std::thread> thread_servers;
		std::stringstream ss;

		for(int i = 0; i < 4; ++i) {

			ss << "3 project/build/" << tests.front() << " 0.1 1";
			thread_servers.push_back(std::thread(serialized, servers.port[i], servers.hostname[i], ss.str()));
			tests.pop();
			ss.str(std::string());
		}

		for(auto& t : thread_servers)
            t.join();
        thread_servers.clear();
        sleep(.5);
	}
}



int main(int count, char *strings[]) {


	//	send_message(6969, "172.17.0.1", "0 ls -la");

	//run_tests_thread();
	run_tests_thread();
/*
	testing_server servers;
	servers.setup_testing_server();
	printf("testing %s \n", servers.build_send_file_string(0, "binary.zip", "/home/ubuntu/testing").c_str());
	send_message(6969, "172.17.0.1", "")
*/

	//return temp2(count, strings);
}
