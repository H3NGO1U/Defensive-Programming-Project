
#pragma once


#include <iostream>
#include <fstream>
#include <string>
#include <aes.h>
#include "RSAWrapper.h"
#include "encode.h"
#include <map>
#include <stdexcept>
#include <thread>
#include <future>
#include "protocol.h"
#include "AESWrapper.h"
#include "crc.h"
#include "file_manager.h"

const uint8_t CLIENT_VERSION = 3;
const uint8_t NUM_OF_TRIALS = 4;

class Client {
private:
	std::string client_name;
	uint8_t client_version;
	std::string client_id;
	std::string aes_key;
	bool registered;
	RequestSenderAndReciever requestSenderAndReciever;
	void read_transfer_info();
	void read_me_info();
	std::string generate_RSA_pair();

	std::string encrypt_with_aes(std::string plain_text);

	/*
	* @brief sends registration request, tries 3 times and then exits
	*/
	void send_registration_request();

	/*
	* @brief sends login request, if rejected moves to registration.
	* Tries 3 times and then exits
	* @return payload_size to accept
	*/
	uint32_t send_login_request();

	/*
	* @brief Sends public key to server
	* Tries 3 times and then exits
	* @return payload_size to accept
	*/
	uint32_t send_public_key();

	/*
	* @brief Registration has been accepted by server, now accept the client id,
	* create me.info file and write client's name and id to it
	*/
	void accept_registration();

	/*
	* @brief Server accepted login/public key, and sends the AES key encrypted.
	* This function recieves it and decrypts it
	*/
	void accept_aes_key(uint16_t payload_size);

	bool accept_crc_and_compare(unsigned long client_crc);
	/*
	* @brief Sending encrypted file to server
	*/
	void send_file();
	void send_crc_ok_conformation(std::string file_name);
	void send_crc_not_ok(std::string file_name);
	void send_crc_not_ok_final(std::string file_name);

	/*
	* @brief Calls the different procedures in the order that the protocol requires
	*/
public:
	Client();
	void start();
};

