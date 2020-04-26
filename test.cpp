#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <string>
#include <dirent.h>
#include <errno.h>
#include <zip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/resource.h>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <stdio.h>      /* printf */
#include <stdarg.h> 

std::string exec(const char* cmd) {

	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

/*
static bool is_dir(const std::string& dir) {

  struct stat st;
  ::stat(dir.c_str(), &st);
  return S_ISDIR(st.st_mode);
}

static void walk_directory(const std::string& startdir, const std::string& inputdir, zip_t *zipper) {

	DIR *dp = ::opendir(inputdir.c_str());
	if (dp == nullptr) {
	   throw std::runtime_error("Failed to open input directory: " + std::string(::strerror(errno)));
	}

	struct dirent *dirp;
	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_name != std::string(".") && dirp->d_name != std::string("..")) {
			std::string fullname = inputdir + "/" + dirp->d_name;
			if (is_dir(fullname)) {
				if (zip_dir_add(zipper, fullname.substr(startdir.length() + 1).c_str(), ZIP_FL_ENC_UTF_8) < 0) {
					throw std::runtime_error("Failed to add directory to zip: " + std::string(zip_strerror(zipper)));
				}
				walk_directory(startdir, fullname, zipper);
			}
			else {
				zip_source_t *source = zip_source_file(zipper, fullname.c_str(), 0, 0);
				if (source == nullptr) {
					throw std::runtime_error("Failed to add file to zip: " + std::string(zip_strerror(zipper)));
				}
				if (zip_file_add(zipper, fullname.substr(startdir.length() + 1).c_str(), source, ZIP_FL_ENC_UTF_8) < 0) {
					zip_source_free(source);
					throw std::runtime_error("Failed to add file to zip: " + std::string(zip_strerror(zipper)));
				}
			}
		}
	}
	::closedir(dp);
}

static void zip_directory(const std::string& inputdir, const std::string& output_filename) {

	int errorp;
	zip_t *zipper = zip_open(output_filename.c_str(), ZIP_CREATE | ZIP_EXCL, &errorp);
	if (zipper == nullptr) {
		zip_error_t ziperror;
		zip_error_init_with_code(&ziperror, errorp);
		throw std::runtime_error("Failed to open output file " + output_filename + ": " + zip_error_strerror(&ziperror));
	}

	try {
		walk_directory(inputdir, inputdir, zipper);
	}
	catch(...) {
		zip_close(zipper);
		throw;
	}
	zip_close(zipper);
}

static void safe_create_dir(const char *dir) {

	if (mkdir(dir, 0755) < 0) {
		if (errno != EEXIST) {
			perror(dir);
			exit(1);
		}
	}
}
 
int un_zip_directory(char *archive) {

	struct zip *za;
	struct zip_file *zf;
	struct zip_stat sb;
	char buf[100];
	int err;
	int i, len;
	int fd;
	long long sum;
 
	if ((za = zip_open(archive, 0, &err)) == NULL) {
		zip_error_to_str(buf, sizeof(buf), err, errno);
		fprintf(stderr, "can't open zip archive `%s': %s\n",
			archive, buf);
		return 1;
	}
 
	for (i = 0; i < zip_get_num_entries(za, 0); i++) {
		if (zip_stat_index(za, i, 0, &sb) == 0) {
			printf("==================\n");
			len = strlen(sb.name);
			printf("Name: [%s], ", sb.name);
			printf("Size: [%llu], ", sb.size);
			printf("mtime: [%u]\n", (unsigned int)sb.mtime);
			if (sb.name[len - 1] == '/') {
				safe_create_dir(sb.name);
			}
			else {
				zf = zip_fopen_index(za, i, 0);
				if (!zf) {
					fprintf(stderr, "boese, boese\n");
					exit(100);
				}
 
				fd = open(sb.name, O_RDWR | O_TRUNC | O_CREAT, 0644);
				if (fd < 0) {
					fprintf(stderr, "boese, boese\n");
					exit(101);
				}
 
				sum = 0;
				while (sum != sb.size) {
					len = zip_fread(zf, buf, 100);
					if (len < 0) {
						fprintf(stderr, "boese, boese\n");
						exit(102);
					}
					write(fd, buf, len);
					sum += len;
				}
				close(fd);
				zip_fclose(zf);
			}
		}
		else {
			printf("File[%s] Line[%d]\n", __FILE__, __LINE__);
		}
	}   
 
	if (zip_close(za) == -1) {
		fprintf(stderr, "can't close zip archive `%s'\n", archive);
		return 1;
	}
	return 0;
}
*/

static std::vector<char> ReadAllBytes(char const* filename)
{
    std::ifstream ifs(filename, std::ios::binary|std::ios::ate);
    std::ifstream::pos_type pos = ifs.tellg();

    std::vector<char>  result(pos);

    ifs.seekg(0, std::ios::beg);
    ifs.read(&result[0], pos);

    return result;
}

static void tte(char* filename)
{
        std::ifstream in(filename, std::ios::binary); //, std::ios::binary
        std::string contents((std::istreambuf_iterator<char>(in)), 
            std::istreambuf_iterator<char>());
                 
        printf("griim: %s\n\n", contents.c_str());

}

static int ttr(char* filename) {

	std::ifstream in;
	in.open(filename, std::ios::in | std::ios::binary);

	// check open file for write
	if (!in.is_open()) {
		std::cerr << "Error in open file './in.bin'" << std::endl;
		return 1;
	}

	// read integer - '111' in hex is '6f'
	int num;
	in.read((char*)&num, sizeof(num));
	std::cout << "Integer: " << num << std::endl;

	// read char - 'e' in hex is '65'
	char ch;
	in.read((char*)&ch, sizeof(ch));
	std::cout << "Char: " << ch << std::endl;

	// close
	in.close();

	return 0;
}
/*
int main(int count, char *strings[]) {

	ttr(strings[1]);

	//std::vector<char> test = ReadAllBytes(strings[1]);

	//for (std::vector<char>::const_iterator i = test.begin(); i != test.end(); ++i)
    //std::cout << *i << ' ';


	//zip_directory("/home/tom/Git/FYP/v4/RamFuzz", "/home/tom/Git/FYP/v4/RamFuzz_zip");

	//printf("%s \n", exec("ls -la").c_str());
}
*/

#include <iostream> 
#include <thread> 
using namespace std; 
  
// A dummy function 
void foo(int Z) 
{ 
    for (int i = 0; i < Z; i++) { 
        cout << "Thread using function"
               " pointer as callable\n"; 
    } 
} 
  
// A callable object 
class thread_obj { 
public: 
    void operator()(int x) 
    { 
        for (int i = 0; i < x; i++) 
            cout << "Thread using function"
                  " object as  callable\n"; 
    } 
}; 

int kek(){
	    cout << "Threads 1 and 2 and 3 "
         "operating independently" << endl; 
  
    // This thread is launched by using  
    // function pointer as callable 
    thread th1(foo, 3); 
  
    // This thread is launched by using 
    // function object as callable 
    thread th2(thread_obj(), 3); 
  
    // Define a Lambda Expression 
    auto f = [](int x) { 
        for (int i = 0; i < x; i++) 
            cout << "Thread using lambda"
             " expression as callable\n"; 
    }; 
  
    // This thread is launched by using  
    // lamda expression as callable 
    thread th3(f, 3); 
  
    // Wait for the threads to finish 
    // Wait for thread t1 to finish 
    th1.join(); 
  
    // Wait for thread t2 to finish 
    th2.join(); 
  
    // Wait for thread t3 to finish 
    th3.join(); 


}

using namespace std;
#define DEBUG 1

inline string get_current_date_time(string s){
    time_t now = time(0);
    struct tm  tstruct;
    char  buf[80];
    tstruct = *localtime(&now);
    if(s=="now")
        strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    else if(s=="date")
        strftime(buf, sizeof(buf), "%Y-%m-%d", &tstruct);
    return string(buf);
};

inline void logger(const char *fmt, ...){

    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    string filePath = "./logs/log_"+get_current_date_time("date")+".txt";
    string now = get_current_date_time("now");
    ofstream ofst(filePath.c_str(), std::ios_base::out | std::ios_base::app );

    if (DEBUG) 
    	cout << now << '\t' << buffer << '\n';

    ofst << now << '\t' << buffer << '\n';
    ofst.close();
}



int main() 
{ 
	logger("kek%s%s", " kekman ", "grim");
  
    return 0; 
} 