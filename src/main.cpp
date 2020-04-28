#include "central_server.h"	
#include "test_server.h"	

int main(int count, char *strings[]) {

    tasks::get_current_dir();
}
/*

int main(int count, char *strings[]) {

	testing_server servers;
	servers.setup_testing_server();

	int server_no = central_server::find_free_server(servers);


	central_server::build_project(server_no, servers);

	servers.in_use[server_no] = false;

	sleep(5);

	vector<int> server_nos = central_server::find_multiple_free_server(4, servers);

	central_server::run_tests_thread(server_nos, servers);
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
    run2(count, strings);
}
*/