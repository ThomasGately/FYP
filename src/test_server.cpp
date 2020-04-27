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
#include <zipper/zipper.h>
#include <zipper/unzipper.h>
#include <zipper/tools.h>
#include <sys/stat.h>

using namespace std;
#define DEBUG 1
#define FAIL -1

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
void ShowCerts(SSL* ssl);
std::string exec_cmd(std::string cmd);
std::string git_clone(std::string git_url);
std::string git_checkout(std::string branch);
std::string run_test(std::string test);
std::string exec_task(std::string input);
void Servlet(SSL* ssl);
void run(int count, char *strings[]);

string hostname;
string current_dir;
string project_dir;
string project_build_dir;
string project_list_of_tests;

string get_current_dir() {

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {

        logger("get_current_dir() error");
    }
    return string(cwd);
}

void zip_files() {

    string project_dir_build_zip = project_dir + "/ziptest.zip";

    remove(project_dir_build_zip.c_str());

    logger("Makeing zip file of build --> %s", project_dir_build_zip.c_str());

    zipper::Zipper zipper(project_dir_build_zip);
    zipper.open();

    logger("Adding dir --> %s", project_build_dir.c_str());

    zipper.add(project_build_dir);
    zipper.close();
}

void un_zip_files() {

    string project_dir_build_zip = project_dir + "/ziptest.zip";    

    logger("Unziping build --> %s", project_dir_build_zip.c_str());

    zipper::Unzipper unzipper(project_dir_build_zip);
    unzipper.extract(project_build_dir);
}

void chmod_tsets_files() {

    std::ifstream list_of_tests(project_list_of_tests);
    std::string line;
    std::string dir_of_test;

    while (list_of_tests >> line) {

        dir_of_test = project_build_dir + line;

        if (chmod(dir_of_test.c_str(), 755) == FAIL) {

            logger("chmod_tsets() error: file --> %s", dir_of_test.c_str());
        }
    }
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
    string filePath = current_dir + "/logs/log_" +  hostname + "_" + get_current_date_time("date") + ".log";
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

std::string exec_cmd(std::string cmd) {

    logger("exec_cmd(std::string cmd) --> %s", cmd.c_str());
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    logger("Result:\n%s", result.c_str());
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

    ss << project_build_dir << "/" << test;

    return exec_cmd(ss.str());
}

std::string build_project(std::string make) {

    std::stringstream ss;

    ss << "bash " << project_dir << "/" << make;

    if (exec_cmd(ss.str()) != "") {

        return "Build failed";
    }
    zip_files();

    return "Build successful";
}


std::string un_zip_build(std::string make) {

    un_zip_files();
    return "Unzip successful";
}

std::string run_bash_script(std::string bash_script) {

    std::stringstream ss;

    ss << "bash " << project_dir << "/" << bash_script;

    return exec_cmd(ss.str());
}

enum tasks {
    task_exec_cmd, 
    task_git_clone,
    task_git_checkout,
    task_run_test,
    task_build_project,
    task_un_zip_build,
    task_run_bash_script
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
        case task_build_project :
            return build_project(input);
            break;
        case task_un_zip_build :
            return un_zip_build(input);
            break;
        case task_run_bash_script :
            return run_bash_script(input);
            break;
        }
}


int OpenListener(int port) {  
 
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

int isRoot() {

    return getuid() ? 0 : 1;
}

SSL_CTX* InitServerCTX(void) {

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

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {

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
        logger("Private key does not match the public certificate");
        abort();
    }
}

void ShowCerts(SSL* ssl) {  

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
    else {
        logger("No certificates.");
    }
}

/* Serve the connection -- threadable */
void Servlet(SSL* ssl) {

    char buf[1024];
    std::string reply;
    int sd, bytes;

    /* do SSL-protocol accept */
    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
    }
    else {

        /* get any certificates */
        ShowCerts(ssl);
        /* get request */
        bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0) {

            buf[bytes] = 0;
            logger("central_server msg: \"%s\"", buf);
            reply = exec_task(std::string(buf));
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

void run(int count, char *strings[]) {

    SSL_CTX *ctx;
    int server;
    char *portnum;

    SSL_library_init();

    portnum = strings[1];
    /* initialize SSL */
    ctx = InitServerCTX();
    /* load certs */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");
    /* create server socket */
    server = OpenListener(atoi(portnum));
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        /* accept connection as usual */
        int client = accept(server, (struct sockaddr*)&addr, &len);
        logger("Connection: %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        /* get new SSL state with context */
        ssl = SSL_new(ctx);
        /* set connection socket to SSL state */
        SSL_set_fd(ssl, client);
        /* service connection */
        Servlet(ssl);
    }
    /* close server socket */
    close(server);
    /* release context */
    SSL_CTX_free(ctx);
}

int main(int count, char *strings[]) {

    if(!isRoot()) {

        logger("This program must be run as root/sudo user!!");
        exit(0);
    }
    if (count != 3) {

        logger("Usage: %s <portnum> <hostname>", strings[0]);
        exit(0);
    }

    current_dir = get_current_dir();
    project_dir = current_dir + "/project";
    project_build_dir = project_dir + "/build";
    project_list_of_tests = project_dir + "/list_of_tests";

    hostname = strings[2];
    run(count, strings);
}