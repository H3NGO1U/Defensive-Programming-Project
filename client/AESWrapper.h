#pragma once

#include <string>



class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = 32;
private:
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESWrapper(const AESWrapper& aes);
public:
	AESWrapper(const char* key, int size);
	~AESWrapper();

	std::string encrypt(const char* plain, unsigned int length);
};







