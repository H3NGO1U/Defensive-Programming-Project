#pragma once
#include <string>
#include <stdint.h>
#include <map>
#include <boost/asio.hpp>
#include <iostream>
#include <fstream>
#include <regex>
#include "encode.h"

extern std::map<std::string, uint16_t> requestCodes;
extern std::map<uint16_t, std::string> statusCodes;

const size_t CHUNK_SIZE = 1024;
const uint8_t SIZE_OF_ID = 16;
const uint8_t SIZE_OF_VERSION_FIELD = 1;
const uint8_t SIZE_OF_CODE_FIELD = 2;
const uint8_t PAYLOAD_SIZE_FIELD_SIZE = 4;
const uint8_t SIZE_OF_FILE_SIZE_FIELD = 4;
const uint8_t SIZE_OF_PACKET_COUNTING = 4;
const uint8_t SIZE_OF_CRC = 4;

//header
const uint8_t SIZE_OF_REQUEST_HEADER = SIZE_OF_ID + SIZE_OF_CODE_FIELD + SIZE_OF_VERSION_FIELD + PAYLOAD_SIZE_FIELD_SIZE;
const uint8_t SIZE_OF_RESPONSE_HEADER = SIZE_OF_CODE_FIELD + SIZE_OF_VERSION_FIELD + PAYLOAD_SIZE_FIELD_SIZE;

//payload
const size_t SIZE_OF_CLIENT_NAME = 255;
const uint32_t SIZE_OF_FILE_NAME = 255;
const size_t SIZE_OF_PUBLIC_KEY = 160;

//requests
const size_t SIZE_OF_REGISTRATION_REQUEST = SIZE_OF_REQUEST_HEADER + SIZE_OF_CLIENT_NAME;
const size_t SIZE_OF_EXCHANGE_KEY_REQUEST = SIZE_OF_REQUEST_HEADER + SIZE_OF_CLIENT_NAME + SIZE_OF_PUBLIC_KEY;
const size_t SIZE_OF_LOGIN_REQUEST = SIZE_OF_REQUEST_HEADER + SIZE_OF_CLIENT_NAME;
const size_t SIZE_OF_CRC_REQUEST = SIZE_OF_REQUEST_HEADER + SIZE_OF_FILE_NAME;

//responses
const size_t SIZE_OF_ACCEPT_CRC = SIZE_OF_ID + SIZE_OF_FILE_SIZE_FIELD + SIZE_OF_FILE_NAME + SIZE_OF_CRC;



class RequestHeader {
public:
	std::string client_id;
	uint8_t client_version;
	uint16_t code;
	uint32_t payload_size;


	RequestHeader(std::string client_id, uint8_t version,  uint16_t code, uint32_t payload_size);
	void pack_for_sending(std::vector<uint8_t>& packet);
};

class ResponseHeader {
public:
	uint8_t server_version;
	uint16_t code;
	uint32_t payload_size;

	ResponseHeader(uint8_t version, uint16_t code, uint32_t payload_size);
};


class Request {
public:
	RequestHeader header;
	Request(RequestHeader header);
};

class RegistrationRequest : public Request {
public:
	std::string client_name;
	RegistrationRequest(RequestHeader header, std::string name);
	void pack_for_sending(std::vector<uint8_t>& packet);
};

class LoginRequest : public Request {
public:
	std::string client_name;
	LoginRequest(RequestHeader header, std::string name);
	void pack_for_sending(std::vector<uint8_t>& packet);
};

class ReconnectionRequest : public Request {
public:
	char client_name[255];
	ReconnectionRequest(RequestHeader header, char* name) : Request(header) {
		strcpy_s(client_name, 255, name);
	}
};

class PublicKeyRequest : public Request {
public:
	std::string client_name;
	std::string public_key;
	PublicKeyRequest(RequestHeader header, std::string name, std::string key);
	void pack_for_sending(std::vector<uint8_t>& packet);
};

class SendingFileRequest : public Request {
public:
	uint32_t content_size;
	uint32_t original_file_size;
	uint16_t packet_number;
	uint16_t total_packets;
	std::string file_name;
	std::string message_content;
	SendingFileRequest(RequestHeader header, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets, std::string file_name, std::string message_content);
	void pack_for_sending(std::vector<uint8_t>& packet);
};


class CRCRequest : public Request {
public:
	std::string file_name;
	CRCRequest(RequestHeader header, std::string name);
	void pack_for_sending(std::vector<uint8_t>& packet);
};


class RequestSenderAndReciever {

private:
	boost::asio::io_context io_context;
	boost::asio::ip::tcp::resolver resolver;
	boost::asio::ip::tcp::socket socket;
public:
	/*
	* @brief constructor of RequestSenderAndReciever
	* Reads the host and port from transfer.info
	*/
	RequestSenderAndReciever();

	/*
	* @brief registration request to the server
	* @param client information to be sent to server
	*/
	void send_registration_request(std::string client_name, std::string client_id, uint8_t client_version);


	/*
	* 
	* @brief login request to the server
	* @param client information to be sent to server
	*/
	void send_login_request(std::string client_name, std::string client_id, uint8_t client_version);

	/*
	* @brief after successful registration, send rsa public key
	* @param client's information to be sent to server
	* @param public key
	*/
	void send_public_key(std::string client_name, std::string public_key, std::string client_id, uint8_t client_version);
	void send_file_in_chunks(std::string client_name, std::string client_id, uint8_t client_version, std::string file_name, std::string file_content, uint32_t original_file_size);
	void send_crc_information(std::string client_id, uint8_t client_version, std::string request_code, std::string file_name);
	/*
	* @brief get the header of the response
	* @return status code, so client knows what to do next
	*/
	ResponseHeader accept_header();

	/*
	* @brief accepts response from server regarding registration
	* @return client id if succeeded, else "0"
	*/
	std::string accept_registration();

	/*
	* @brief accepts response from server regarding aes and successful sending of rsa
	* @return aes key if succeeded, else "0"
	*/

	std::string accept_aes_key(uint16_t payload_size);

	/*
	* @brief accept login failed response - typically the client id that was rejected
	*/
	void accept_login_failed();
	uint32_t accept_crc();
	void accept_msg_conformation();
};






ResponseHeader unpack_recieved_header(std::vector<uint8_t>& packet);
void prepare_payload_for_sending(std::string& field_content, size_t field_size);
