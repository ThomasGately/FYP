//test_server.cpp
#include "test_server.h"

using namespace std;

int test_server::open_listener(int port) {  
 
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {

		perror("can't bind port");
		abort();
	}
	if (listen(sd, 10) != 0) {

		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

int test_server::is_root(void) {

	return getuid() ? 0 : 1;
}

SSL_CTX* test_server::init_server_CTX(void) {

	const SSL_METHOD *method;
	SSL_CTX *ctx;

	/* load & register all cryptos, etc. */
	OpenSSL_add_all_algorithms();
	/* load all error messages */
	SSL_load_error_strings();
	/* create new server-method instance */
	method = TLSv1_2_server_method();
	/* create new context from method */
	ctx = SSL_CTX_new(method);
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void test_server::load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {

	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx))
	{
		tasks::logger("Private key does not match the public certificate");
		abort();
	}
}

void test_server::show_certs(SSL* ssl) {  

	X509 *cert;
	char *line;

	/* Get certificates (if available) */
	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {

		tasks::logger("Server certificates:");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		tasks::logger("Subject: %s", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		tasks::logger("Issuer: %s", line);
		free(line);
		X509_free(cert);
	}
	else {
		tasks::logger("No certificates.");
	}
}

/* Serve the connection -- threadable */
void test_server::servlet(SSL* ssl) {

	char buf[1024];
	std::string reply;
	int sd, bytes;

	/* do SSL-protocol accept */
	if (SSL_accept(ssl) == FAIL) {
		ERR_print_errors_fp(stderr);
	}
	else {

		/* get any certificates */
		show_certs(ssl);
		/* get request */
		bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes > 0) {

			buf[bytes] = 0;
			tasks::logger("central_server msg: \"%s\"", buf);
			reply = tasks::exec_task(std::string(buf));
			/* send reply */
			SSL_write(ssl, reply.c_str(), strlen(reply.c_str()));
		}
		else {
			ERR_print_errors_fp(stderr);
		}
	}
	/* get socket connection */
	sd = SSL_get_fd(ssl);
	/* release SSL state */
	SSL_free(ssl);
	/* close connection */
	close(sd);
}

/* run the server */
void test_server::run_openssl(int port) {

	SSL_CTX *ctx;
	int server;

	SSL_library_init();

	/* initialize SSL */
	ctx = init_server_CTX();
	/* load certs */
	load_certificates(ctx, "mycert.pem", "mycert.pem");
	/* create server socket */
	server = open_listener(port);
	while (1)
	{   struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;

		/* accept connection as usual */
		int client = accept(server, (struct sockaddr*)&addr, &len);
		tasks::logger("Connection: %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		/* get new SSL state with context */
		ssl = SSL_new(ctx);
		/* set connection socket to SSL state */
		SSL_set_fd(ssl, client);
		/* service connection */
		servlet(ssl);
	}
	/* close server socket */
	close(server);
	/* release context */
	SSL_CTX_free(ctx);
}

/* run the server */
void test_server::run_sockaddr(int port) { 

	int server_fd, new_socket, valread; 
	struct sockaddr_in address; 
	int opt = 1; 
	int addrlen = sizeof(address); 
	char buffer[1024] = {0}; 
	std::string reply;

	/* Creating socket file descriptor */
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)  { 

		perror("socket failed"); 
		exit(EXIT_FAILURE); 
	} 

	/* Forcefully attaching socket to the port */
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {

		perror("setsockopt"); 
		exit(EXIT_FAILURE); 
	} 
	address.sin_family = AF_INET; 
	address.sin_addr.s_addr = INADDR_ANY; 
	address.sin_port = htons(port); 
	   
	/* Forcefully attaching socket to the port */
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {

		perror("bind failed"); 
		exit(EXIT_FAILURE); 
	} 
	if (listen(server_fd, 3) < 0) { 
		perror("listen"); 
		exit(EXIT_FAILURE); 
	}
	while (1) {
		if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {

			perror("accept"); 
			exit(EXIT_FAILURE); 
		}
		valread = read(new_socket, buffer, sizeof(buffer));
		if (valread > 0) {

			tasks::logger("central_server msg: \"%s\"", buffer);
			reply = tasks::exec_task(std::string(buffer));
			/* send reply */
			send(new_socket, reply.c_str(), strlen(reply.c_str()), 0);
		} 
	}
}

void test_server::run(int port, string _hostname) {

	if(!is_root()) {

		tasks::logger("This program must be run as root/sudo user!!");
		exit(0);
	}
	hostname = _hostname;
	if (OPENSSL == true) {
		return run_openssl(port);
	}
	return run_sockaddr(port);
}