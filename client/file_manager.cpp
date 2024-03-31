#include "file_manager.h"


std::string FileManager::read_private_key() {
	std::ifstream private_key_file("priv.key");
	std::string line;
	std::string base64key;
	if (private_key_file.is_open()) {
		while (std::getline(private_key_file, line)) {
			base64key += line;
		}
	}
	else {
		throw std::runtime_error("\nError opening private key file for reading\n");
	}
	return base64key;
}

std::string FileManager::read_file_path() {
	std::ifstream transfer_info_file("transfer.info");
	std::string file_path;
	if (transfer_info_file.is_open()) {
		std::string line;
		//reading the third line, which should hold the file path
		std::getline(transfer_info_file, line);
		std::getline(transfer_info_file, line);
		std::getline(transfer_info_file, file_path);
		transfer_info_file.close();
	}
	else {
		throw std::runtime_error("\ntransfer.info file is missing\n");
	}
	return file_path;
}


std::string FileManager::get_file_content(std::string file_path) {
	std::cout << "\nreading file to send\n";
	std::string line;
	std::string file_content;
	std::ifstream file_to_send(file_path, std::ios::binary);
	if (file_to_send.is_open()) {
		std::stringstream buffer;
		buffer << file_to_send.rdbuf();
		file_to_send.close();
		file_content = buffer.str();
		std::cout << "\nFinished reading\n";
		std::cout << "----------------------------------------\n";
	}
	else {
		throw std::runtime_error("\nError opening " + file_path + " file for reading\n");
	}
	return file_content;
}


std::string FileManager::get_file_name(std::string path) {
	std::filesystem::path file_path(path);
	return file_path.filename().string();
}
