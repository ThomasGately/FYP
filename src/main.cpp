#include "central_server.h"	
#include "test_server.h"	

int main(int count, char *strings[]) {

	tasks::get_current_dir();
    tasks::set_dirs(current_dir + "/project", current_dir + "/project/build", current_dir + "/project/list_of_tests");

    /* run central_server eg ./build/main central_server test_on_pis */
	if (count == 3 && strcmp(strings[1], "central_server") == 0) {

		if (strcmp(strings[1], "test_on_pis") == 0) {
			central_server::test_on_pis();
		}
		else if (strcmp(strings[1], "test_on_pi") == 0) {
			central_server::test_on_pi();
		}
		else if (strcmp(strings[1], "test_on_localhost") == 0) {
			central_server::test_on_localhost();
		}
	}
    /* run test_server eg ./build/main test_server 8000 127.0.0.1 */
	else if (count == 4 && strcmp(strings[1], "test_server") == 0) {

		test_server::run(atoi(strings[2]), string(strings[3]));
	}
}