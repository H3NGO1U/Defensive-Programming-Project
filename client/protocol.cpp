
#include "protocol.h"

std::map<std::string, uint16_t> requestCodes = {
		{"registration", 1025},
		{"send_public_key", 1026},
		{"login", 1027},
		{"send_file", 1028},
		{"CRC_ok", 1029},
		{"CRC_resend", 1030},
		{"CRC_bad", 1031}
};


std::map<uint16_t, std::string> statusCodes = {
	 {1600, "registration_success"},
	 {1601, "registration_failed"},
	 {1602, "sending_AES"},
	 {1603, "accepted_file"},
	 {1604, "msg_accepted"},
	 {1605, "login_ok_sending_AES"},
	 {1606, "login_rejected"},
	 {1607, "server_error"}
};

Request::Request(RequestHeader header) : header(header) {}


RequestHeader::RequestHeader(std::string client_id, uint8_t client_version, uint16_t code, uint32_t payload_size) : code(code), client_version(client_version), payload_size(payload_size) {
	this->client_id = client_id;
}

void RequestHeader::pack_for_sending(std::vector<uint8_t>& packet) {

	packet.insert(packet.end(), this->client_id.begin(), this->client_id.end());

	packet.push_back(this->client_version);

	uint8_t buffer16[2];
	memcpy_s(buffer16, sizeof(buffer16), &(this->code), sizeof(uint16_t));
	packet.insert(packet.end(), buffer16, buffer16 + sizeof(uint16_t));

	uint8_t buffer32[4];
	memcpy_s(buffer32, sizeof(buffer32), &payload_size, sizeof(uint32_t));
	packet.insert(packet.end(), buffer32, buffer32 + sizeof(uint32_t));
}




ResponseHeader::ResponseHeader(uint8_t version, uint16_t code, uint32_t payload_size) : code(code), server_version(version), payload_size(payload_size) {}

ResponseHeader unpack_recieved_header(std::vector<uint8_t>& packet) {
	uint8_t server_version;
	server_version = packet[0];
	uint16_t response_code;
	memcpy(&response_code, &packet[SIZE_OF_VERSION_FIELD], sizeof(uint16_t));
	uint32_t payload_size;
	memcpy(&payload_size, &packet[SIZE_OF_VERSION_FIELD + SIZE_OF_CODE_FIELD], sizeof(uint32_t));
	ResponseHeader header(server_version, response_code, payload_size);
	return header;
}



RegistrationRequest::RegistrationRequest(RequestHeader header, std::string name) : Request(header), client_name(name) {}

void RegistrationRequest::pack_for_sending(std::vector<uint8_t>& packet) {
	this->header.pack_for_sending(packet);
	std::string client_name_field = this->client_name;
	prepare_payload_for_sending(client_name_field, SIZE_OF_CLIENT_NAME);
	packet.insert(packet.end(), client_name_field.begin(), client_name_field.end());
}

LoginRequest::LoginRequest(RequestHeader header, std::string name) : Request(header), client_name(name) {}

void LoginRequest::pack_for_sending(std::vector<uint8_t>& packet) {
	this->header.pack_for_sending(packet);
	std::string client_name_field = this->client_name;
	prepare_payload_for_sending(client_name_field, SIZE_OF_CLIENT_NAME);
	packet.insert(packet.end(), client_name_field.begin(), client_name_field.end());
}

PublicKeyRequest::PublicKeyRequest(RequestHeader header, std::string name, std::string key) : Request(header), client_name(name), public_key(key) {}

void PublicKeyRequest::pack_for_sending(std::vector<uint8_t>& packet) {
	this->header.pack_for_sending(packet);

	std::string client_name_field = this->client_name;
	std::string public_key_field = this->public_key;

	prepare_payload_for_sending(client_name_field, SIZE_OF_CLIENT_NAME);
	packet.insert(packet.end(), client_name_field.begin(), client_name_field.end());
	packet.insert(packet.end(), public_key_field.begin(), public_key_field.end());
}

SendingFileRequest::SendingFileRequest(RequestHeader header, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets, std::string file_name, std::string message_content) :
	Request(header), content_size(content_size), original_file_size(original_file_size), packet_number(packet_number), total_packets(total_packets), file_name(file_name), message_content(message_content){}

void SendingFileRequest::pack_for_sending(std::vector<uint8_t>& packet) {
	this->header.pack_for_sending(packet);

	uint8_t content_size_buffer[4];
	memcpy_s(content_size_buffer, sizeof(content_size_buffer), &(this->content_size), sizeof(uint32_t));
	packet.insert(packet.end(), content_size_buffer, content_size_buffer + sizeof(uint32_t));
	
	uint8_t original_file_size_buffer[4];
	memcpy_s(original_file_size_buffer, sizeof(original_file_size_buffer), &(this->original_file_size), sizeof(uint32_t));
	packet.insert(packet.end(), original_file_size_buffer, original_file_size_buffer + sizeof(uint32_t));

	uint8_t packet_number_buffer[2];
	memcpy_s(packet_number_buffer, sizeof(packet_number_buffer), &(this->packet_number), sizeof(uint16_t));
	packet.insert(packet.end(), packet_number_buffer, packet_number_buffer + sizeof(uint16_t));

	uint8_t total_packets_buffer[2];
	memcpy_s(total_packets_buffer, sizeof(total_packets_buffer), &(this->total_packets), sizeof(uint16_t));
	packet.insert(packet.end(), total_packets_buffer, total_packets_buffer + sizeof(uint16_t));

	std::string file_name_field = this->file_name;
	prepare_payload_for_sending(file_name_field, SIZE_OF_FILE_NAME);
	packet.insert(packet.end(), file_name_field.begin(), file_name_field.end());
	packet.insert(packet.end(), message_content.begin(), message_content.end());
}



CRCRequest::CRCRequest(RequestHeader header, std::string name) : Request(header), file_name(name) {}

void CRCRequest::pack_for_sending(std::vector<uint8_t>& packet) {
	this->header.pack_for_sending(packet);
	std::string file_name_field = this->file_name;
	prepare_payload_for_sending(file_name_field, SIZE_OF_FILE_NAME);
	packet.insert(packet.end(), file_name_field.begin(), file_name_field.end());
}


void prepare_payload_for_sending(std::string& field_content, size_t field_size) {
	if (field_content.length() >= field_size) {
		std::cerr << "\nPayload is too long, potential data loss...\n";
		field_content = field_content.substr(0, field_size-1);
	}
	while (field_content.length() < field_size) {
		field_content.push_back('\0');
	}
}



bool is_valid_IP_address(const std::string& ip) {
	const std::regex ip_regex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
	return std::regex_match(ip, ip_regex);
}

bool is_valid_port(const std::string& port) {
	try {
		int port_num = std::stoi(port);
		return (port_num >= 0 && port_num <= 65535);
	}
	catch (const std::exception& e) {
		return false;
	}
}

RequestSenderAndReciever::RequestSenderAndReciever() :resolver(io_context)
	, socket(io_context) {
	
	std::ifstream transfer_info("transfer.info");
	std::string transfer_address;
	std::string host;
	std::string port;
	if (transfer_info.is_open()) {
		std::getline(transfer_info, transfer_address);
		size_t colon_position = transfer_address.find(':');
		if (colon_position == std::string::npos) {
			throw std::runtime_error("\nError: no colon found in IP and port line\n");
		}
		host = transfer_address.substr(0, colon_position);
		port = transfer_address.substr(colon_position + 1);
		std::cout << "\nhost: " << host << " port: " << port;
		transfer_info.close();
	}
	else {
		throw std::runtime_error("\ntransfer.info file is missing\n");
	}
	if (!is_valid_IP_address(host))
		throw std::runtime_error("\nHost is not a valid IP address\n");
	if (!is_valid_port(port))
		throw std::runtime_error("\nPort is not a valid port number\n");
	
	boost::asio::connect(socket, resolver.resolve(host, port));
}


void RequestSenderAndReciever::send_registration_request(std::string client_name, std::string client_id, uint8_t client_version) {
	RequestHeader header(client_id, client_version, requestCodes["registration"], SIZE_OF_CLIENT_NAME);
	RegistrationRequest request(header, client_name);
	std::vector<uint8_t> packet;
	request.pack_for_sending(packet);
	boost::asio::write(this->socket, boost::asio::buffer(packet, SIZE_OF_REGISTRATION_REQUEST));
	std::cout << "sent";
}


void RequestSenderAndReciever::send_public_key(std::string client_name, std::string public_key, std::string client_id, uint8_t client_version) {
	RequestHeader header(client_id, client_version, requestCodes["send_public_key"], SIZE_OF_EXCHANGE_KEY_REQUEST - SIZE_OF_REQUEST_HEADER);
	PublicKeyRequest request(header, client_name, public_key);
	std::vector<uint8_t> packet;
	request.pack_for_sending(packet);
	boost::asio::write(this->socket, boost::asio::buffer(packet, SIZE_OF_EXCHANGE_KEY_REQUEST));
}


void RequestSenderAndReciever::send_login_request(std::string client_name, std::string client_id, uint8_t client_version) {
	RequestHeader header(client_id, client_version, requestCodes["login"], SIZE_OF_CLIENT_NAME);
	LoginRequest request(header, client_name);
	std::vector<uint8_t> packet;
	request.pack_for_sending(packet);
	boost::asio::write(this->socket, boost::asio::buffer(packet, SIZE_OF_LOGIN_REQUEST));
}


void RequestSenderAndReciever::send_file_in_chunks(std::string client_name, std::string client_id, uint8_t client_version, std::string file_name, std::string file_content, uint32_t original_file_size) {
	size_t size_of_encrypted_file = file_content.length();
	size_t total_packets = size_of_encrypted_file / CHUNK_SIZE + 1;
	std::cout << "\nTotal packets to send: " << total_packets << "\n";
	size_t packet_number = 1;
	size_t start_position = 0;
	while (packet_number <= total_packets) {
		std::string chunk_content = file_content.substr(start_position, CHUNK_SIZE);
		uint16_t payload_size = SIZE_OF_FILE_SIZE_FIELD * 2 + SIZE_OF_PACKET_COUNTING + SIZE_OF_FILE_NAME + chunk_content.length();
		RequestHeader header(client_id, client_version, requestCodes["send_file"], payload_size);
		SendingFileRequest request(header, size_of_encrypted_file, original_file_size, packet_number, total_packets, file_name, chunk_content);
		std::vector<uint8_t> packet;
		request.pack_for_sending(packet);
		boost::asio::write(this->socket, boost::asio::buffer(packet, SIZE_OF_REQUEST_HEADER + payload_size));
		std::cout << "\nPacket number " << packet_number << " has been sent\n";
		packet_number++;
		start_position += CHUNK_SIZE;
	}
}
 
void RequestSenderAndReciever::send_crc_information(std::string client_id, uint8_t client_version, std::string request_code, std::string file_name) {
	RequestHeader header(client_id, client_version, requestCodes[request_code], SIZE_OF_FILE_NAME);
	CRCRequest request(header, file_name);
	std::vector<uint8_t> packet;
	request.pack_for_sending(packet);
	boost::asio::write(this->socket, boost::asio::buffer(packet, SIZE_OF_CRC_REQUEST));
}



ResponseHeader RequestSenderAndReciever::accept_header() {
	std::vector<uint8_t> packet(SIZE_OF_RESPONSE_HEADER);
	boost::asio::read(socket, boost::asio::buffer(packet, SIZE_OF_RESPONSE_HEADER));
	ResponseHeader header = unpack_recieved_header(packet);
	return header;
}


std::string RequestSenderAndReciever::accept_aes_key(uint16_t payload_size) {
	
	std::vector<uint8_t> packet(payload_size);
	boost::asio::read(socket, boost::asio::buffer(packet, payload_size));

	std::string client_id(packet.begin(), packet.begin()+SIZE_OF_ID);
	std::string aes_key(packet.begin() + SIZE_OF_ID, packet.end());
	
	return aes_key;

}

std::string RequestSenderAndReciever::accept_registration() {
	std::vector<uint8_t> packet(SIZE_OF_ID);
	boost::asio::read(socket, boost::asio::buffer(packet, SIZE_OF_ID));
	std::string client_id(packet.begin(), packet.end());
	return client_id;
}

void RequestSenderAndReciever::accept_login_failed() {
	std::vector<uint8_t> packet(SIZE_OF_ID);
	boost::asio::read(socket, boost::asio::buffer(packet, SIZE_OF_ID));
	std::string client_id(packet.begin(), packet.end());
}





uint32_t RequestSenderAndReciever::accept_crc() {
	std::vector<uint8_t> packet(SIZE_OF_ACCEPT_CRC);
	boost::asio::read(socket, boost::asio::buffer(packet, SIZE_OF_ACCEPT_CRC));
	std::string client_id(packet.begin(), packet.begin()+SIZE_OF_ID);
	uint32_t content_size;
	memcpy(&content_size, &packet[SIZE_OF_ID], sizeof(uint32_t));

	size_t starting_point = SIZE_OF_ID + SIZE_OF_FILE_SIZE_FIELD;
	std::string file_name(packet.begin()+starting_point, packet.begin() + starting_point + SIZE_OF_FILE_NAME);

	starting_point += SIZE_OF_FILE_NAME;
	uint32_t server_crc;
	memcpy(&server_crc, &packet[starting_point], sizeof(uint32_t));
	return server_crc;
}


void RequestSenderAndReciever::accept_msg_conformation() {
	std::vector<uint8_t> packet(SIZE_OF_ID);
	boost::asio::read(socket, boost::asio::buffer(packet, SIZE_OF_FILE_NAME));
	std::string client_id(packet.begin(), packet.end());
}
