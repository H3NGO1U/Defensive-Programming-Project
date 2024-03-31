#include "encode.h"


std::string Encoder::b64encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}



std::string Encoder::b64decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}

std::string Encoder::hexify(const char* buffer, unsigned int length)
{
	std::ostringstream oss;
	oss << std::hex;
	for (size_t i = 0; i < length; i++)
	{
		oss << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : "");
	}
	return oss.str();
}

std::string Encoder::dehexify(const std::string& hexString) {
	std::string result;
	unsigned int byte;

	for (size_t i = 0; i < hexString.size(); i += 2) {
		std::istringstream iss(hexString.substr(i, 2));
		if (!(iss >> std::hex >> byte)) {
			throw std::runtime_error("Invalid client id: not a hexadecimal string");
		}
		result.push_back(static_cast<char>(byte));
	}

	return result;
}