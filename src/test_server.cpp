//test_server.cpp
#include "test_server.h"

using namespace std;

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

int run2(int count, char *strings[]) 
{ 
    int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024] = {0}; 
    string portnum = strings[1];
    std::string reply;

    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( stoi(portnum) ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }
    while (1) {
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    }
    valread = read(new_socket, buffer, sizeof(buffer));
    if (valread > 0) {

        logger("central_server msg: \"%s\"", buffer);
        reply = tasks::exec_task(std::string(buffer));
        /* send reply */
        send(new_socket, reply.c_str(), strlen(reply.c_str()), 0);
    } 
}
    return 0; 
}