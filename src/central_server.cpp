//central_server.cpp

#include "central_server.h"

int central_server::send_message(int port, string hostname, tasks::enum_tasks task, string message) {

	if (OPENSSL == true) {
		return send_message_openssl(port, hostname, task, message);
	}
	return send_message_sockaddr(port, hostname, task, message);
}
   
int central_server::send_message_sockaddr(int port, string hostname, tasks::enum_tasks task, string message) {

	stringstream ss;

	ss << task << " " << message;

	message = ss.str();

    tasks::logger("message %s", message.c_str());
 
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
    tasks::logger("Connected with %s", hostname.c_str());
    send(sock, message.c_str(), strlen(message.c_str()), 0); 
    valread = read( sock , buffer, 1024); 
    tasks::logger("Received: \"%s\"", buffer);
    return 0; 
}

int central_server::send_message_openssl(int port, std::string hostname, tasks::enum_tasks task, std::string message) {
	
	int ret = 0;

	stringstream ss;

	ss << task << " " << message;

	message = ss.str();

	tasks::logger("send_message_openssl message --> %s", message.c_str());

	if (my_re_lock() && my_wr_lock()) {
		SSL_CTX *ctx;
		SSL *ssl;
		int server;
		char buf[1024];
		int bytes;

		ctx = init_CTX();

		server = open_connection(hostname.c_str(), port);

		//create new SSL connection state 
		ssl = SSL_new(ctx);
		//attach the socket descriptor
		SSL_set_fd(ssl, server);

		//perform the connection
		if (SSL_connect(ssl) == FAIL) {
			ERR_print_errors_fp(stderr);
		}
		else {
			tasks::logger("Connected with %s encryption", SSL_get_cipher(ssl));
			//encrypt & send message
			SSL_write(ssl, message.c_str(), strlen(message.c_str()));
			//get reply & decrypt
			bytes = SSL_read(ssl, buf, sizeof(buf));
			buf[bytes] = 0;

			if (string(buf).find("failure") != std::string::npos) {
				//tasks::error_logger("failure --> \"%s\"", buf);
			}
			tasks::logger("Received: \"%s\"", buf);
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

CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
CRYPTO_RWLOCK *wr_lock;
CRYPTO_RWLOCK *re_lock;

void central_server::my_init(void) {

	SSL_library_init();		
	wr_lock = CRYPTO_THREAD_lock_new();
	re_lock = CRYPTO_THREAD_lock_new();
}

int central_server::my_wr_lock(void) {

	if (!CRYPTO_THREAD_run_once(&once, my_init) || wr_lock == NULL)
		return 0;

	return CRYPTO_THREAD_write_lock(wr_lock);
}

int central_server::my_re_lock(void) {

	if (!CRYPTO_THREAD_run_once(&once, my_init) || re_lock == NULL)
		return 0;

	return CRYPTO_THREAD_read_lock(re_lock);
}

int central_server::my_wr_unlock(void) {
	return CRYPTO_THREAD_unlock(wr_lock);
}


int central_server::my_re_unlock(void) {
	return CRYPTO_THREAD_unlock(re_lock);
}

int central_server::open_connection(const char *hostname, int port) {

	int sd;
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

SSL_CTX* central_server::init_CTX(void) {

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

void central_server::show_certs(SSL* ssl) {
	
	X509 *cert;
	char *line;

	/* get the server's certificate */
	cert = SSL_get_peer_certificate(ssl); 
	if ( cert != NULL )
	{
		tasks::logger("Server certificates:");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		tasks::logger("Subject: %s", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		tasks::logger("Issuer: %s", line);
		free(line);       /* free the malloc'ed string */
		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		tasks::logger("Info: No client certificates configured.");
}

void central_server::show_queue(std::queue<std::string> input_queue) {

	std::queue <std::string> queue_print = input_queue; 
	while(!queue_print.empty())  {

		tasks::logger("show_queue --> %s", queue_print.front()); 
		queue_print.pop(); 
	}
}

string central_server::send_build_files_to_test_server(int server_no, struct str_testing_server servers, string path_to_file, string path_to_destination) {

	tasks::logger("send_build_files_to_central\n path_to_file --> %s\n path_to_destination --> %s", path_to_file.c_str(), path_to_destination.c_str());

	stringstream ss;

	//sshpass -p "kekman69" scp binary.zip ubuntu@192.168.1.34:/home/ubuntu/testing 
	ss << "scp " << path_to_file << ' ' << servers.username[server_no] << '@' << servers.hostname[server_no] << ':' << path_to_destination;

	tasks::logger("send_build_files_to_central --> %s", ss.str().c_str());

	send_message(servers.port[server_no], servers.hostname[server_no], tasks::task_un_zip_build, "task_un_zip_build");

	return tasks::exec_cmd(ss.str().c_str());
}


string central_server::send_build_files_to_central(int server_no, struct str_testing_server servers, string path_to_file, string path_to_destination) {

	tasks::logger("send_build_files_to_central\n path_to_file --> %s\n path_to_destination --> %s", path_to_file.c_str(), path_to_destination.c_str());

	stringstream ss;

	//scp binary.zip ubuntu@192.168.1.34:/home/ubuntu/testing 
	ss << "scp " << servers.username[server_no] << '@' << servers.hostname[server_no] << ':' << path_to_file << ' ' << path_to_destination;

	tasks::logger("send_build_files_to_central --> %s", ss.str().c_str());

	send_message(servers.port[server_no], servers.hostname[server_no], tasks::task_un_zip_build, "task_un_zip_build");

	return tasks::exec_cmd(ss.str().c_str());
}


void central_server::run_tests(int i, struct str_testing_server servers) {

	std::ifstream list_of_tests("project/list_of_tests");
	std::queue<std::string> tests;
	std::string line;

	while (list_of_tests >> line) {
		tests.push(line);
	}

	while(!tests.empty()) {

		std::stringstream ss;
		ss << tests.front() << " 0.1 1";
		send_message(servers.port[i], servers.hostname[i], tasks::task_run_test, ss.str());
		tests.pop(); 
	}
}

void central_server::run_tests_thread(vector<int> server_nos, struct str_testing_server servers) {

	ifstream list_of_tests("project/list_of_tests");
	queue<string> tests;
	string line;

	for (int i = 0; i < server_nos.size(); ++i) {

		//send_build_files_to_test_server(server_nos[i], servers, current_dir + "/project/ziptest.zip", "/home/ubuntu/FYP/project/ziptest.zip");
	}

	while (list_of_tests >> line) {
		tests.push(line);
	}

	vector<thread> thread_servers;

	while(!tests.empty()) {

		stringstream ss;

		for(int i = 0; i < server_nos.size(); ++i) {

			ss << tests.front() << " 1 2";
			thread_servers.push_back(thread(send_message, servers.port[server_nos[i]], servers.hostname[server_nos[i]], tasks::task_run_test, ss.str()));
			tests.pop();
			ss.str(string());
		}
		for(auto& t : thread_servers) {
            t.join();
		}
		thread_servers.clear();
	}  
}

int central_server::find_free_server(struct str_testing_server &servers) {

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

vector<int> central_server::find_multiple_free_server(int no_of_servers, struct str_testing_server servers) {

	vector<int> found_severs;

	for (int i = 0; i < no_of_servers; ++i) {

		int temp = find_free_server(servers);
		found_severs.push_back(temp);
		tasks::logger("find_free_server --> %s", servers.hostname[found_severs[i]].c_str());
		
	}
	return found_severs;
}

void central_server::build_project(int server_no, struct str_testing_server servers) {

	//send_message(servers.port[server_no], servers.hostname[server_no], task_run_bash_script, "clean.sh");

	send_message(servers.port[server_no], servers.hostname[server_no], tasks::task_build_project, "make.sh 10");
}

void central_server::test_on_localhost() {

	str_testing_server servers;
	servers.setup_testing_server_localhost();

	int server_no = find_free_server(servers);

	build_project(server_no, servers);

	tasks::exec_cmd("rm /project/build/testxx*");

	send_build_files_to_central(0, servers, current_dir + "project/ziptest.zip", current_dir + "/project/ziptest.zip");

	run_tests(0, servers);
}

void central_server::test_on_pi() {

	str_testing_server servers;
	servers.setup_testing_server();

	int server_no = find_free_server(servers);

	build_project(server_no, servers);

	//send_build_files_to_central(server_no, servers, "/home/ubuntu/FYP/project/ziptest.zip", current_dir + "/project/ziptest.zip");

	servers.in_use[server_no] = false;

	vector<int> server_nos = find_multiple_free_server(1, servers);

	run_tests_thread(server_nos, servers);
}

void central_server::test_on_pis() {

	str_testing_server servers;
	servers.setup_testing_server();

	int server_no = find_free_server(servers);

	build_project(server_no, servers);

	//send_build_files_to_central(server_no, servers, "/home/ubuntu/FYP/project/ziptest.zip", current_dir + "/project/ziptest.zip");

	servers.in_use[server_no] = false;


	vector<int> server_nos = find_multiple_free_server(4, servers);

	run_tests_thread(server_nos, servers);
}