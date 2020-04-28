#ifndef TASKS_H
#define TASKS_H
//tasks.h

#include <string>
#include <linux/limits.h>
#include <unistd.h>
#include <stdarg.h>
#include <fstream>
#include <iostream>
#include <array>
#include <sstream>
#include <memory>
#include <zipper/zipper.h>
#include <zipper/unzipper.h>
#include <zipper/tools.h>
#include <sys/stat.h>
#include <openssl/err.h>

using namespace std;
#define DEBUG 0
#define FAIL -1
#define OPENSSL 0

static string current_dir;
static string project_dir;
static string project_build_dir;
static string project_list_of_tests;

class tasks {

public:
	enum enum_tasks {
		task_exec_cmd, 
		task_git_clone,
		task_git_checkout,
		task_run_test,
		task_build_project,
		task_un_zip_build,
		task_run_bash_script
	};
	static string exec_cmd(string cmd);
	static string exec_task(string input);
	static void logger(const char *fmt, ...);
	static void error_logger(const char *fmt, ...);
	static void set_dirs(string _project_dir, string _project_build_dir, string _project_list_of_tests);

private:
	static string git_clone(string git_url);
	static string git_checkout(string branch);
	static string run_test(string test);
	static string build_project(string make);
	static string un_zip_build(string make);
	static string run_bash_script(string bash_script);
	static inline void log(int type, const char *fmt, ...);
	static inline void openssl_logger();
	static inline string get_current_date_time(string s);
	static void zip_files();
	static void un_zip_files();
	static void chmod_tsets_files();
};

#endif