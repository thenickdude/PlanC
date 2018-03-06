#pragma once

#include <cstdio>
#include <cstdint>
#include <string>
#include <iostream>

std::string hexStringToBin(std::string input);
std::string binStringToHex(std::string input);
std::string base64Decode(const char *buffer, int length);
std::string base64Decode(const std::string buffer);

int64_t readInt64BE(uint8_t* &buffer);
int64_t readInt64BE(FILE *file);

int32_t readInt32BE(uint8_t* &buffer);
int32_t readInt32BE(FILE *file);

int16_t readInt16BE(uint8_t* &buffer);
int16_t readInt16BE(FILE *file);

int8_t readInt8(uint8_t* &buffer);
int8_t readInt8(FILE *file);

uint8_t readUInt8(uint8_t* &buffer);
uint8_t readUInt8(FILE *file);

void readBytes(uint8_t *dest, uint8_t* &buffer, size_t count);
void readBytes(uint8_t *dest, FILE* file, size_t count);

std::string readStreamAsString(std::istream &in);

std::string maybeDecompress(const std::string &buffer);