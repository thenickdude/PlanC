#define __STDC_FORMAT_MACROS
#define _POSIX_C_SOURCE 200112L
#define _FILE_OFFSET_BITS 64

#include <cassert>
#include <sstream>

#include "common.h"

#include "cryptopp/modes.h"
#include "cryptopp/base64.h"

#include "zstr/src/zstr.hpp"

int64_t readInt64BE(uint8_t* &buffer) {
	int64_t result = ((int64_t) buffer[0] << 56) | ((int64_t) buffer[1] << 48) | ((int64_t) buffer[2] << 40) | ((int64_t) buffer[3] << 32)
					 | ((int64_t) buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7];

	buffer += 8;

	return result;
}

int64_t readInt64BE(FILE *file) {
	uint8_t buffer[sizeof(int64_t)];

	fread((char*) buffer, sizeof(buffer), 1, file);

	return ((int64_t) buffer[0] << 56) | ((int64_t)buffer[1] << 48) | ((int64_t)buffer[2] << 40) | ((int64_t) buffer[3] << 32)
		   | ((int64_t) buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7];
}

int32_t readInt32BE(uint8_t* &buffer) {
	int32_t result = (buffer[0] << 24) |  (buffer[1] << 16) | (buffer[2] << 8) |  buffer[3];

	buffer += 4;

	return result;
}

int32_t readInt32BE(FILE *file) {
	uint8_t buffer[sizeof(int32_t)];

	fread((char*) buffer, sizeof(buffer), 1, file);

	return (buffer[0] << 24) |  (buffer[1] << 16) | (buffer[2] << 8) |  buffer[3];
}

int16_t readInt16BE(uint8_t* &buffer) {
	int16_t result = (buffer[0] << 8) | buffer[1];

	buffer += 2;

	return result;
}

int16_t readInt16BE(FILE *file) {
	uint8_t buffer[sizeof(int16_t)];

	fread((char*) buffer, sizeof(buffer), 1, file);

	return (buffer[0] << 8) | buffer[1];
}

int8_t readInt8(uint8_t* &buffer) {
	int8_t result = (int8_t) buffer[0];

	buffer++;

	return result;
}

int8_t readInt8(FILE *file) {
	uint8_t buffer[1];

	fread((char*) buffer, sizeof(buffer), 1, file);

	return (int8_t) buffer[0];
}

uint8_t readUInt8(uint8_t* &buffer) {
	uint8_t result = buffer[0];

	buffer++;

	return result;
}

uint8_t readUInt8(FILE *file) {
	uint8_t buffer[1];

	fread((char*) buffer, sizeof(buffer), 1, file);

	return buffer[0];
}

void readBytes(uint8_t *dest, uint8_t* &buffer, size_t count) {
	memcpy(dest, buffer, count);
	buffer += count;
}

void readBytes(uint8_t *dest, FILE* file, size_t count) {
	fread(dest, 1, count, file);
}

uint8_t hexNibbleToInt(char n) {
	if (n >= '0' && n <= '9') {
		return (uint8_t) (n - '0');
	}
	if (n >= 'a' && n <= 'f') {
		return (uint8_t) (n - 'a' + 10);
	}
	return (uint8_t) (n - 'A' + 10);
}

char intToHexNibble(int i) {
	if (i < 10) {
		return (char) (i + '0');
	}
	return (char) ((i - 10) + 'A');
}

std::string hexStringToBin(std::string input) {
	int outputLength = input.length() / 2;
	char *buffer = new char[outputLength];
	int dest = 0;
	int source = 0;

	for (; source < input.length(); dest++, source += 2) {
		buffer[dest] = (hexNibbleToInt(input[source]) << 4) | hexNibbleToInt(input[source + 1]);
	}

	std::string result(buffer, outputLength);

	delete [] buffer;

	return result;
}

std::string binStringToHex(std::string input) {
	char *buffer = new char[input.length() * 2 + 1];
	int dest = 0;
	int source = 0;

	for (; source < input.length(); dest += 2, source++) {
		buffer[dest] = intToHexNibble(((uint8_t) input[source]) >> 4);
		buffer[dest + 1] = intToHexNibble(((uint8_t) input[source]) & 0x0F);
	}

	buffer[dest] = '\0';

	std::string result(buffer);

	delete [] buffer;

	return result;
}

std::string base64Decode(const char *buffer, int length) {
	CryptoPP::Base64Decoder decoder;

	decoder.Put((const CryptoPP::byte *)buffer, length);
	decoder.MessageEnd();

	std::string result;

	int resultSize = decoder.MaxRetrievable();

	if (resultSize) {
		result.resize(resultSize);
		decoder.Get((CryptoPP::byte *) &result[0], result.length());
	}

	return result;
}

std::string base64Decode(const std::string buffer) {
	return base64Decode(buffer.data(), buffer.length());
}

std::string readStreamAsString(std::istream &in) {
	std::string result;
	char buffer[4096];

	while (in.read(buffer, sizeof(buffer))) {
		result.append(buffer, sizeof(buffer));
	}

	result.append(buffer, in.gcount());

	return result;
}

std::string maybeDecompress(const std::string &buffer) {
	std::istringstream ss(buffer, std::ios_base::in);
	zstr::istream decompress(ss);

	return readStreamAsString(decompress);
}
