#pragma once

#include "leveldb/db.h"

#include <vector>
#include <utility>

void adbInitPlatformKeys(const std::string &macOSSerial, const std::string &linuxSerial);
leveldb::DB* adbOpen(std::string adbPath);
bool adbKeyExists(leveldb::DB* db, std::string key);
std::string adbReadKey(leveldb::DB* db, std::string key);
std::string adbReadSecureKey(leveldb::DB* db, std::string key, std::string password);
bool adbReadAllKeys(leveldb::DB* db, std::vector<std::pair<std::string, std::string>> &result);
