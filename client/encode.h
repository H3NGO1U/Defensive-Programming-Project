#pragma once

#include <string>
#include <base64.h>
#include <iomanip>

class Encoder
{
public:
	static std::string b64encode(const std::string& str);
	static std::string b64decode(const std::string& str);
	static std::string hexify(const char* buffer, unsigned int length);
	static std::string dehexify(const std::string& hexString);
};


