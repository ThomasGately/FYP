#include "tasks.h"

	
string tasks::exec_cmd(string cmd) {

	logger("exec_cmd(string cmd) --> %s", cmd.c_str());
	array<char, 128> buffer;
	string result;
	unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
	if (!pipe) {
		throw runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	logger("Result:\n%s", result.c_str());
	return result;
}

string tasks::git_clone(string git_url) {

	stringstream ss;

	ss << "git clone " << git_url;

	return exec_cmd(ss.str());
}

string tasks::git_checkout(string branch) {

	stringstream ss;

	ss << "git checkout " << branch;

	return exec_cmd(ss.str());
}

string tasks::run_test(string test) {

	stringstream ss;

	ss << project_build_dir << "/" << test;

	return exec_cmd(ss.str());
}

string tasks::build_project(string make) {

	stringstream ss;

	ss << "bash " << project_dir << "/" << make;

	if (exec_cmd(ss.str()) != "") {

		return "Build failed";
	}
	zip_files();

	return "Build successful";
}


string tasks::un_zip_build(string make) {

	un_zip_files();
	return "Unzip successful";
}

string tasks::run_bash_script(string bash_script) {

	stringstream ss;

	ss << "bash " << project_dir << "/" << bash_script;

	return exec_cmd(ss.str());
} 

string tasks::exec_task(string input) {

	enum_tasks task = static_cast<enum_tasks>(stoi(input.substr(0, 1)));
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

void tasks::get_current_dir(void) {

	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd)) == NULL) {

		logger("get_current_dir() error");
	}
	current_dir = string(cwd);
}

void tasks::set_dirs(string _project_dir, string _project_build_dir, string _project_list_of_tests) {

	project_dir = _project_dir;
	project_build_dir = _project_build_dir;
	project_list_of_tests = _project_list_of_tests;
}

inline void tasks::log(int type, const char *fmt, ...) {

	char buffer[4096];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	string filePath = current_dir + "/logs/log_central_server_" + get_current_date_time("date") + ".log";
	string now = get_current_date_time("now");
	ofstream ofst;
	ofst.open(filePath.c_str(), std::ios_base::out | std::ios_base::app );

	if (!ofst) {
		ofst.open(filePath.c_str(), fstream::out | fstream::trunc);
	}

	if (DEBUG) {
		cout << now << '\t' << buffer << '\n';
	}
	else if (type) {
		cout << now << '\t' << buffer << '\n';
	}
}

inline void tasks::logger(const char *fmt, ...) {

	va_list args;
	va_start(args, fmt);
	log(0, fmt, args);
	va_end(args);
}

inline void tasks::error_logger(const char *fmt, ...) {

	va_list args;
	va_start(args, fmt);
	log(1, fmt, args);
	va_end(args);
}

inline void tasks::openssl_logger(void) {

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

inline string tasks::get_current_date_time(string s) {

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

void tasks::zip_files(void) {

	string project_dir_build_zip = project_dir + "/ziptest.zip";

	remove(project_dir_build_zip.c_str());

	logger("Makeing zip file of build --> %s", project_dir_build_zip.c_str());

	zipper::Zipper zipper(project_dir_build_zip);
	zipper.open();

	logger("Adding dir --> %s", project_build_dir.c_str());

	zipper.add(project_build_dir);
	zipper.close();
}

void tasks::un_zip_files(void) {

	string project_dir_build_zip = project_dir + "/ziptest.zip";    

	logger("Unziping build --> %s", project_dir_build_zip.c_str());

	zipper::Unzipper unzipper(project_dir_build_zip);
	unzipper.extract(project_build_dir);
}

void tasks::chmod_tsets_files(void) {

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