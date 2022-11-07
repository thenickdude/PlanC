#include <cassert>
#include <cstdio>

#include "adb.h"
#include "common.h"
#include "crypto.h"
#include "comparator.h"

#include "cryptopp/sha.h"

static const std::string OBFUSCATION_KEY = "HWANToDk3L6hcXryaU95X6fasmufN8Ok";

static Code42AES256RandomIV aes256;

leveldb::DB* adbOpen(std::string adbPath) {
	leveldb::DB* db;
	leveldb::Options options;
	Code42Comparator *comp = new Code42Comparator();

	options.create_if_missing = false;
	options.compression = leveldb::CompressionType::kNoCompression;
	options.comparator = comp;

	leveldb::Status status = leveldb::DB::Open(options, adbPath, &db);

	if (!status.ok()) {
		throw std::runtime_error(status.ToString());
	}

	return db;
}

std::string adbReadKey(leveldb::DB* db, std::string key) {
	std::string value;
	leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);

	if (status.ok()) {
		return aes256.decrypt(value, OBFUSCATION_KEY);
	} else {
		throw std::runtime_error("Failed to fetch " + key + ": " + status.ToString());
	}
}

bool adbKeyExists(leveldb::DB* db, std::string key) {
	std::string value;
	leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);

	return status.ok();
}

std::string adbReadSecureKey(leveldb::DB* db, std::string key, std::string password) {
	std::string value = base64Decode(adbReadKey(db, key));

	if (passwordUnlocksSecureDataKey(value, password)) {
		return decryptSecureDataKey(value, password);
	} else {
		throw std::runtime_error("The provided password couldn't decrypt the " + key + ", is the password correct?");
	}
}

bool adbReadAllKeys(leveldb::DB* db, std::vector<std::pair<std::string, std::string>> &result) {
	leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());

	for (it->SeekToFirst(); it->Valid(); it->Next()) {
		/*
		 * We avoid calling decryptAndPrintValueForKey here, because if our comparator is wrong then we expect iteration
		 * to find keys that ->Get() can't see.
		 */
		result.push_back(std::pair<std::string,std::string>(it->key().ToString(), aes256.decrypt(it->value().ToString(), OBFUSCATION_KEY)));
	}

	bool success = it->status().ok();

	delete it;

	return success;
}