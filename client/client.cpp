

#include "client.h"

#pragma pack(push,1)



Client::Client():
	client_version(CLIENT_VERSION), requestSenderAndReciever() {
	read_me_info();
}

void Client::read_transfer_info() {
	std::ifstream transfer_info_file("transfer.info");
	if (transfer_info_file.is_open()) {
		std::string line;
		std::getline(transfer_info_file, line); //first line is host and port, not relevant to this layer
		std::string client_name;
		std::getline(transfer_info_file, client_name);
		transfer_info_file.close();
		if (!this->registered) { //if registered: the client name has been read from me.info
			this->client_name = client_name;
			this->client_id = std::string(16, '0'); //some default
		}
	}
	else {
		throw std::runtime_error("\ntransfer.info file is missing\n");
	}
}

void Client::read_me_info() {
	std::ifstream client_info_file("me.info");
	std::string client_info;
	std::string client_id_hex;
	if (client_info_file.is_open()) {
		this->registered = true;
		std::getline(client_info_file, this->client_name);
		client_info += "\nName: " + this->client_name + "\n";
		std::getline(client_info_file, client_id_hex);
		client_info += "\nID: " + client_id_hex + "\n";
		this->client_id = Encoder::dehexify(client_id_hex);
		std::cout << "\nme.info file exists\n";
		std::cout << "\nClient's information: \n" << client_info;
		std::cout << "\nMoving to login request...\n";
		client_info_file.close();
	}
	else {
		this->registered = false;
		std::cout << "\nme.info file doesn't exist\n";
		std::cout << "\nMoving to registration request...\n";
	}
}




std::string Client::generate_RSA_pair() {
	std::cout << "\nGenerating RSA keys...\n";
	RSAPrivateWrapper rsapriv;
	std::string base64key = Encoder::b64encode(rsapriv.getPrivateKey());
	std::ofstream private_key_file("priv.key");
	if (private_key_file.is_open()) {
		private_key_file << base64key;
		private_key_file.close();
	}

	else {
		throw std::runtime_error("\nError opening private key file for writing\n");
	}

	std::ofstream client_info_file("me.info", std::ios::app);
	if (client_info_file.is_open()) {
		client_info_file << base64key;
		client_info_file.close();
	}
	else {
		throw std::runtime_error("\nError opening me.info file for writing\n");
	}

	std::cout << "\nDone\n";
	std::cout << "----------------------------------------\n";
	return rsapriv.getPublicKey();
}


std::string Client::encrypt_with_aes(std::string plain_text) {
	AESWrapper aes(this->aes_key.c_str(), this->aes_key.length());
	std::string cipher_text = aes.encrypt(plain_text.c_str(), plain_text.length());
	return cipher_text;
}


// requests

void Client::send_registration_request() {
	std::cout << "\nSending registration request\n";
	std::string response_status = "";
	read_transfer_info();
	for (uint8_t trial = 0; trial < NUM_OF_TRIALS;  trial++) {
		requestSenderAndReciever.send_registration_request(this->client_name, this->client_id, this->client_version);
		ResponseHeader header = requestSenderAndReciever.accept_header();
		response_status = statusCodes[header.code];
		if (response_status != "registration_success")
			std::cerr << "\nserver responded with an error\n";
		else {
			std::cout << "\nRegistration accepted\n";
			accept_registration();
			std::cout << "----------------------------------------\n";
			return;
		}
	}
	throw std::runtime_error("\nFATAL: server has reponded with "+response_status+"\n");
}


uint32_t Client::send_login_request() {
	std::cout << "\nSending login request\n";
	std::string response_status = "";
	for (uint8_t trial = 0; trial < NUM_OF_TRIALS; trial++) {
		requestSenderAndReciever.send_login_request(this->client_name, this->client_id, this->client_version);
		ResponseHeader header = requestSenderAndReciever.accept_header();
		response_status = statusCodes[header.code];
		std::cout << "\nResponse message: " << response_status << "\n";
		if (response_status == "login_rejected") {
			std::cerr << "\nlogin rejected by server, switching to registration...\n";
			std::cout << "----------------------------------------\n";
			this->registered = false; 
			requestSenderAndReciever.accept_login_failed();
			return 0;
		}
		if (response_status != "login_ok_sending_AES")
			std::cerr << "\nServer responded with an error\n";

		else {
			std::cout << "\nLogin accepted by server\n";
			std::cout << "----------------------------------------\n";
			return header.payload_size;
		}
	}
	throw std::runtime_error("\nFATAL: server has reponded with " + response_status + "\n");
	//return 0;
}


uint32_t Client::send_public_key() {
	std::string public_key = generate_RSA_pair();
	std::cout << "\nSending public key\n";
	std::string response_status = "";
	for (uint8_t trial = 0; trial < NUM_OF_TRIALS; trial++) {
		requestSenderAndReciever.send_public_key(this->client_name, public_key, this->client_id, this->client_version);
		ResponseHeader header = requestSenderAndReciever.accept_header();
		response_status = statusCodes[header.code];
	
		std::cout << "\nResponse message: " << response_status << "\n";
		if (response_status != "sending_AES")
			std::cerr << "\nserver responded with an error\n";

		else {
			std::cout << "\npublic key accepted by server\n";
			std::cout << "----------------------------------------\n";
			return header.payload_size;
		}
	}
	throw std::runtime_error("\nFATAL: server has reponded with " + response_status + "\n");

}


void Client::send_file() {
	std::string file_path = FileManager::read_file_path();
	std::string file_content = FileManager::get_file_content(file_path);
	std::future<unsigned long> crc_future = std::async(calc_crc,file_path);
	std::string encrypted_file_contents = encrypt_with_aes(file_content);
	std::string file_name = FileManager::get_file_name(file_path);
	unsigned long client_crc = crc_future.get();
	std::string response_status = "";
	for (uint8_t trial = 0; trial < NUM_OF_TRIALS; trial++) {
		requestSenderAndReciever.send_file_in_chunks(this->client_name, this->client_id, this->client_version, file_name, encrypted_file_contents, file_content.length());
		ResponseHeader header = requestSenderAndReciever.accept_header();
		response_status = statusCodes[header.code];

		std::cout << "\nResponse message: " << response_status << "\n";
		if (response_status != "accepted_file")
			std::cerr << "\nserver responded with an error\n";

		else {
			std::cout << "\nfile accepted by server\n";
			std::cout << "\nmoving to crc comparison...\n";
			std::cout << "----------------------------------------\n";
			bool crc_ok = accept_crc_and_compare(client_crc);
			if (crc_ok) {
				send_crc_ok_conformation(file_name);
				return;
			}
			else if(trial<NUM_OF_TRIALS-1){ //not last trial
				send_crc_not_ok(file_name);
			}
			else { //last trial
				send_crc_not_ok_final(file_name);
			}
		}
	}
}


void Client::send_crc_ok_conformation(std::string file_name) {
	std::string response_status = "";
	for (uint8_t trial = 0; trial < NUM_OF_TRIALS; trial++) {
		requestSenderAndReciever.send_crc_information(this->client_id, this->client_version, "CRC_ok", file_name);
		ResponseHeader header = requestSenderAndReciever.accept_header();
		response_status = statusCodes[header.code];

		std::cout << "\nResponse message: " << response_status << "\n";
		if (response_status != "msg_accepted")
			std::cerr << "\nserver responded with an error\n";

		else {
			requestSenderAndReciever.accept_msg_conformation();
			std::cout << "\nmessage accepted by server\n";
			std::cout << "----------------------------------------\n\n\n";
			return;
		}
	}
	throw std::runtime_error("\nFATAL: server has reponded with " + response_status + "\n");
}


void Client::send_crc_not_ok(std::string file_name) {
	requestSenderAndReciever.send_crc_information(this->client_id, this->client_version, "CRC_resend", file_name);
	std::cout << "\nCRC not ok message has been sent\n";
	std::cout << "----------------------------------------\n";
}

void Client::send_crc_not_ok_final(std::string file_name) {
	std::string response_status = "";
	for (uint8_t trial = 0; trial < NUM_OF_TRIALS; trial++) {
		requestSenderAndReciever.send_crc_information(this->client_id, this->client_version, "CRC_bad", file_name);
		std::cout << "\nCRC not ok FINAL message has been sent\n";
		ResponseHeader header = requestSenderAndReciever.accept_header();
		response_status = statusCodes[header.code];

		std::cout << "\nResponse message: " << response_status << "\n";
		if (response_status != "msg_accepted")
			std::cerr << "\nserver responded with an error\n";

		else {
			requestSenderAndReciever.accept_msg_conformation();
			std::cout << "\nmessage accepted by server\n";
			std::cout << "----------------------------------------\n\n\n";
			return;

		}
	}
	throw std::runtime_error("\nFATAL: server has reponded with " + response_status + "\n");
}


//responses

void Client::accept_aes_key(uint16_t payload_size) {
	if (payload_size <= 0) {
		throw std::runtime_error("\nAES key cannot be of negative or zero lenght\n");
	}
	std::cout << "\naccepting aes key...\n";
	std::string message = requestSenderAndReciever.accept_aes_key(payload_size);
	std::string private_key = Encoder::b64decode(FileManager::read_private_key());
	RSAPrivateWrapper rsapriv(private_key);
	this->aes_key = rsapriv.decrypt(message);
	std::cout << "\ndone\n";
	std::cout << "----------------------------------------\n";
}


void Client::accept_registration() {
	std::string client_id = requestSenderAndReciever.accept_registration();

	this->client_id = client_id;
	std::cout << "Client ID: " << Encoder::hexify(this->client_id.c_str(), 16) << "\n";
	std::ofstream client_info_file("me.info");
	if (client_info_file.is_open()) {
		client_info_file << this->client_name << "\n" << Encoder::hexify(this->client_id.c_str(), 16);
		client_info_file.close();
	}

	else {
		throw std::runtime_error("\nError writing to me.info file\n");
	}
}

bool Client::accept_crc_and_compare(unsigned long client_crc) {
	uint32_t server_crc = requestSenderAndReciever.accept_crc();
	std::cout << "\nclient crc: " << client_crc << "\n";
	std::cout << "\nserver crc: " << server_crc << "\n";
	if (server_crc == client_crc) {
		std::cout << "\nEqual\n";
		return true;
	}
	else {
		std::cout << "\nNot equal, resend...\n";
		return false;
	}
}

void Client::start() {
	uint32_t payload_size;
	if (this->registered) {
		payload_size = send_login_request(); // if login is rejected that this->registered becomes false
	}
	if (!this->registered) {
		send_registration_request();
		payload_size = send_public_key();
	}
	accept_aes_key(payload_size);
	send_file();
}

#pragma pack(pop)


