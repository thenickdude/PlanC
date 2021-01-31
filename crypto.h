#pragma once

#include <string>
#include <stdexcept>

#define CIPHER_CODE_MIN               0

#define CIPHER_CODE_NONE              0
#define CIPHER_CODE_BLOWFISH_128      1
#define CIPHER_CODE_BLOWFISH_448      2
#define CIPHER_CODE_AES_128           3
#define CIPHER_CODE_AES_256           4
#define CIPHER_CODE_AES_256_RANDOM_IV 5

#define CIPHER_CODE_MAX               5

inline bool isValidCipherCode(uint8_t code) {
	return code >= CIPHER_CODE_MIN && code <= CIPHER_CODE_MAX;
}

class BadPaddingException : public std::runtime_error {
public:
	BadPaddingException() : std::runtime_error("Bad padding") {
	}
};

class Code42Cipher {
public:
	virtual std::string decrypt(const std::string & cipherText, const std::string & key) const = 0;
};

class Code42NullCipher : public Code42Cipher {
	std::string decrypt(const std::string & cipherText, const std::string & key) const override {
		return cipherText;
	}
};

class Code42Blowfish448 : public Code42Cipher {
public:
	std::string decrypt(const std::string & cipherText, const std::string &key) const override;
};

class Code42Blowfish128 : public Code42Blowfish448 {
public:
	std::string decrypt(const std::string & cipherText, const std::string &key) const override {
		return Code42Blowfish448::decrypt(cipherText, key.substr(0, 128 / 8));
	}
};

class Code42AESStaticIV : public Code42Cipher {
public:
	std::string decrypt(const std::string & cipherText, const std::string &key) const override;
};

class Code42AES128 : public Code42AESStaticIV {
public:
	std::string decrypt(const std::string & cipherText, const std::string &key) const override {
		return Code42AESStaticIV::decrypt(cipherText, key.substr(0, 128 / 8));
	}
};

class Code42AES256 : public Code42AESStaticIV {
public:
	std::string decrypt(const std::string & cipherText, const std::string &key) const override {
		return Code42AESStaticIV::decrypt(cipherText, key.substr(0, 256 / 8));
	}
};

class Code42AES256RandomIV : public Code42Cipher {
public:
	std::string decrypt(const std::string & cipherText, const std::string &key) const override;
};

// Use CIPHER_CODE_* as indexes:
extern const Code42Cipher* code42Ciphers[];

std::string deriveCustomArchiveKeyV2(const std::string &userID, const std::string &passphrase);