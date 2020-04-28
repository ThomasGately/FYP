//central_server.c

#include "central_server.h"
#include <benchmark/benchmark.h>

static void BM_build_project(benchmark::State& state) {

	current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server();

	int server_no = find_free_server(servers);

	for (auto _ : state){
		build_project(server_no, servers);
	}
}

static void BM_test_on_pi(benchmark::State& state) {

	current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server();

	vector<int> server_nos = find_multiple_free_server(1, servers);
	
	for (auto _ : state) {
		run_tests_thread(server_nos, servers);
	}
}

static void BM_test_on_4_pis(benchmark::State& state) {

	current_dir = get_current_dir();
	testing_server servers;
	servers.setup_testing_server();

	vector<int> server_nos = find_multiple_free_server(4, servers);
	
	for (auto _ : state) {
		run_tests_thread(server_nos, servers);
	}

}

BENCHMARK(BM_build_project);
BENCHMARK(BM_test_on_pi);
BENCHMARK(BM_test_on_4_pis);

BENCHMARK_MAIN();

/*
int main(int count, char *strings[]) {

	//test_on_pis();
}
*/