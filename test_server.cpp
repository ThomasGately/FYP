//test_erver.c
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
#include <stdarg.h>
#include <stdio.h> 

using namespace std;

#define DEBUG 0
#define FAIL 1

inline string get_current_date_time(string s){
    time_t now = time(0);
    struct tm  tstruct;
    char  buf[80];
    tstruct = *localtime(&now);

    if(s=="now")
        strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    else if(s=="date")
        strftime(buf, sizeof(buf), "%Y-%m-%d", &tstruct);

    return string(buf);
};

inline void logger(const char *fmt, ...){

    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    string filePath = "./logs/log_"+get_current_date_time("date")+".txt";
    string now = get_current_date_time("now");
    ofstream ofst(filePath.c_str(), std::ios_base::out | std::ios_base::app );

    if (DEBUG) 
        cout << now << '\t' << buffer << '\n';

    ofst << now << '\t' << buffer << '\n';
    ofst.close();
}

inline void openssl_logger(){

    FILE* file;
    string filePath = "./logs/log_"+get_current_date_time("date")+".txt";
    file = fopen(filePath.c_str(), "r");

    if (DEBUG) {
        ERR_print_errors_fp(stderr);
    }
    else {
        ERR_print_errors_fp(file);
    }
}

int open_listener(int port) {

    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {

        openssl_logger();
        abort();
    }
    if (listen(sd, 10) != 0) {

        openssl_logger();
        abort();
    }
    return sd;
}

int is_root() {

    return getuid() ? 0 : 1;
}

SSL_CTX* init_server_CTX(void) {

    const SSL_METHOD *method;
    SSL_CTX *ctx;

    /* load all error messages */
    OpenSSL_add_all_algorithms();
    /* create new server-method instance */
    SSL_load_error_strings();
    method = TLSv1_2_server_method();
    /* create new context from method */
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL ) {
        openssl_logger();
        abort();
    }
    return ctx;
}

void load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {

    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {

        openssl_logger();
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {

        openssl_logger();
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {

        logger("Private key does not match the public certificate");
        abort();
    }
}

void show_certs(SSL* ssl) {

    X509 *cert;
    char *line;

    /* Get certificates (if available) */
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {

        logger("Server certificates:");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        logger("Subject: %s", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        logger("Issuer: %s", line);
        free(line);
        X509_free(cert);
    }
    else
        logger("No certificates.\n");
}

std::string exec_cmd(std::string cmd) {

    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    logger("\n %s \n", result.c_str());
    return result;
}

std::string git_clone(std::string git_url) {

    std::stringstream ss;

    ss << "git clone " << git_url;

    return exec_cmd(ss.str());
}

std::string git_checkout(std::string branch) {

    std::stringstream ss;

    ss << "git checkout " << branch;

    return exec_cmd(ss.str());
}

std::string run_test(std::string test) {

    std::stringstream ss;

    ss << "./" << test;

    return exec_cmd(ss.str());
}

enum tasks {
    task_exec_cmd, 
    task_git_clone,
    task_git_checkout,
    task_run_test
}; 

std::string exec_task(std::string input) {

    tasks task = static_cast<tasks>(std::stoi(input.substr(0, 1)));
    input.erase(0, 2);

    switch(task) {
        case task_exec_cmd :
            return exec_cmd(input);
            break;
        case task_git_clone :
            return git_clone(input);
            break;
        case task_git_checkout :
            return git_checkout(input);
            break;
        case task_run_test :
            return run_test(input);
            break;
    }
}


void servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char buf[1024];
    std::string reply;
    int sd, bytes;

    if (SSL_accept(ssl) == FAIL)     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        show_certs(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            logger("central_server msg: \"%s\"\n", buf);
            reply = exec_task(std::string(buf));
            SSL_write(ssl, reply.c_str(), strlen(reply.c_str())); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

int main(int count, char *strings[]) {

    SSL_CTX *ctx;
    int server;
    char *portnum;

    if(!is_root())
    {
        logger("This program must be run as root/sudo user!!\n");
        exit(0);
    }
    if ( count != 2 )
    {
        logger("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();

    portnum = strings[1];
    ctx = init_server_CTX();        /* initialize SSL */
    load_certificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = open_listener(atoi(portnum));    /* create server socket */
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        logger("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        servlet(ssl);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
