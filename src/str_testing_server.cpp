#include "str_testing_server.h"

void str_testing_server::setup_testing_server() {

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
}

void str_testing_server::setup_testing_server_localhost() {

	port.push_back(6969);
	in_use.push_back(false);
	name.push_back("my pc");
	hostname.push_back("192.168.1.21");
	username.push_back("tom");

	++no_of_servers;
}