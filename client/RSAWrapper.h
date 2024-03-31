#pragma once

#include <osrng.h>
#include <rsa.h>

#include <string>


class RSAPrivateWrapper
{
public:
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;
public:
	RSAPrivateWrapper();
	RSAPrivateWrapper(const std::string& key);
	~RSAPrivateWrapper();

	std::string getPrivateKey() const;
	std::string getPublicKey() const;
	std::string decrypt(const std::string& cipher);
};
