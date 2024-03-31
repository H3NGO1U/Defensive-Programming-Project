#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>

class FileManager {
public:
	static std::string read_private_key();
	static std::string read_file_path();
	static std::string get_file_content(std::string file_path);
	static std::string get_file_name(std::string path);
};

