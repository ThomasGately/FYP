#ifndef STR_TSETIING_SERVER_H_
#define STR_TSETIING_SERVER_H_
//str_testing_server.h

#include "tasks.h"

#include <vector>
#include <string>
#include <sstream>

using namespace std;


struct str_testing_server {

	int no_of_servers = 0;
	vector<int> port;
	vector<int> in_use;
	vector<string> name;
	vector<string> hostname;
	vector<string> username;

	void setup_testing_server();
	void setup_testing_server_localhost();
};

#endif