#include <cassert>
#include <cstdio>

#include "adb.h"
#include "common.h"
#include "crypto.h"

#include "leveldb/comparator.h"

#include "cryptopp/sha.h"

static const std::string OBFUSCATION_KEY = "HWANToDk3L6hcXryaU95X6fasmufN8Ok";

static Code42AES256RandomIV aes256;
static Code42Blowfish448 blowfish;

class Code42Comparator : public leveldb::Comparator {
	public:
	Code42Comparator() { }

	virtual const char* Name() const {
		return "code42.archive.v2.virtual.table";
	}

	virtual int Compare(const leveldb::Slice& a, const leveldb::Slice& b) const {
		return a.compare(b);
	}

	void FindShortestSeparator(std::string*, const leveldb::Slice&) const {}
	void FindShortSuccessor(std::string*) const {}
};

static uint32_t decodeUInt32BE(const char *buffer) {
	uint8_t *bytes = (uint8_t *) buffer;

	return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

/**
 * Check if the given account password can be used to unlock the given ArchiveSecureDataKey. The key must be deobfuscated
 * and base64-decoded first.
 */
static bool passwordUnlocksSecureDataKey(const std::string &decoded, const std::string &password) {
	/* ArchiveSecureDataKey has this format:
	 *
	 * Start    Content
	 * 0        Length of key bytes as a big-endian 4 byte integer
	 * 4        Key bytes
	 * 4 + len  Password hash, being:
	 *            Hash - SHA-1 of salt||password, then SHA-1 applied to the resulting hash for 4242 iterations, finally base64 encoded
	 *               : - colon separator
	 *            Salt - 8 byte random salt, base64 encoded
	 */
	const int SHA1_ITERATIONS = 4242;

	const char *keyAndPasswordHash = decoded.c_str();
	int keyLen = decodeUInt32BE(keyAndPasswordHash);
	int hashAndSaltLen = decoded.length() - keyLen - 4;

	const char *key = keyAndPasswordHash + 4;
	const char *hashAndSalt = key + keyLen;

	const char *separator = strchr(hashAndSalt, ':');

	assert(separator != NULL);

	const char *hash = hashAndSalt;
	const char *salt = separator + 1;
	int hashLen = salt - hash - 1;
	int saltLen = (hashAndSalt + hashAndSaltLen) - salt;

	std::string hashDecoded, saltDecoded;

	saltDecoded = base64Decode(salt, saltLen);
	hashDecoded = base64Decode(hash, hashLen);

	CryptoPP::SHA1 hasher;
	CryptoPP::byte currentHash[CryptoPP::SHA1::DIGESTSIZE];

	hasher.Update((const CryptoPP::byte*) saltDecoded.data(), saltDecoded.length());
	hasher.Update((const CryptoPP::byte*) password.data(), password.length());

	hasher.Final(currentHash);

	for (int i = 0; i < SHA1_ITERATIONS; i++) {
		hasher.Update(currentHash, sizeof(currentHash));
		hasher.Final(currentHash);
	}

	return memcmp(hashDecoded.data(), currentHash, sizeof(currentHash)) == 0;
}

static std::string decryptSecureDataKey(const std::string &decoded, const std::string & password) {
	const char *keyAndPasswordHash = decoded.c_str();

	// Slice the encrypted key out of the start of the key/password hash pair:
	int encryptedKeyLen = decodeUInt32BE(keyAndPasswordHash);
	std::string encryptedKey = std::string(keyAndPasswordHash + 4, encryptedKeyLen);

	// Then decrypt it with the user's account password as the key
	return blowfish.decrypt(encryptedKey, password);
}

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