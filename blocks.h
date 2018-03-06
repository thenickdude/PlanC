#pragma once

#include <vector>

#include "boost/filesystem/path.hpp"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/md5.h"

#include "common.h"
#include "crypto.h"

#define BLOCK_STATE_NORMAL  0
#define BLOCK_STATE_DELETED -2

#define DATA_BLOCK_TYPE_UNKNOWN       -1
// Lower 4 bits are the CIPHER_CODE_*
#define DATA_BLOCK_TYPE_CIPHER_MASK   15
#define DATA_BLOCK_TYPE_GZIP_FLAG     16
#define DATA_BLOCK_TYPE_ZLIB_FLAG     32


class DataBlock {
public:
	int64_t blockNum;

	int sourceLen;
	int sourceChecksum;
	CryptoPP::byte sourceMD5[CryptoPP::Weak::MD5::DIGESTSIZE];

	int8_t type;

	int backupLen;
	CryptoPP::byte backupMD5[CryptoPP::Weak::MD5::DIGESTSIZE];

	bool isCompressed() const {
		return type == DATA_BLOCK_TYPE_UNKNOWN ? true : (type & (DATA_BLOCK_TYPE_GZIP_FLAG | DATA_BLOCK_TYPE_ZLIB_FLAG)) != 0;
	}

	bool isEncrypted() const {
		return getCipher() != CIPHER_CODE_NONE;
	}

	uint8_t getCipher() const {
		return type == DATA_BLOCK_TYPE_UNKNOWN ? CIPHER_CODE_BLOWFISH_128 : (uint8_t) (type & DATA_BLOCK_TYPE_CIPHER_MASK);
	}

	template<typename T>
	void readFrom(T& stream) {
		blockNum = readInt64BE(stream);
		sourceLen = readInt32BE(stream);
		sourceChecksum = readInt32BE(stream);
		readBytes(sourceMD5, stream, sizeof(sourceMD5));
		type = readInt8(stream);
		backupLen = readInt32BE(stream);
		readBytes(backupMD5, stream, sizeof(backupMD5));
	}
};

class BlockManifestEntry {
public:
	int64_t offset;
	int8_t state;

	bool isValid() const {
		return offset >= 0 && state >= 0;
	}
};

class BlockManifest {
private:
	std::vector<BlockManifestEntry> entries;
	FILE *blockData;
	int blockDataHandle;

public:
	boost::filesystem::path directoryPath;
	int64_t firstBlockNum;

	BlockManifest(const boost::filesystem::path path, int64_t firstBlockNum) : directoryPath(path), firstBlockNum(firstBlockNum) {
	}

	void open();

	bool containsBlock(int64_t blockNumber) const;
	int64_t getDataOffsetForBlock(int64_t blockNumber) const;

	DataBlock readBlockHeader(int64_t blockNumber) const;
	std::string readBlockData(int64_t blockNumber, int len) const;

	bool operator < (const BlockManifest& that) const {
		return firstBlockNum < that.firstBlockNum;
	}
};

class BlockDirectories {
private:
	boost::filesystem::path rootPath;
	std::vector<BlockManifest> directories;

	const BlockManifest& getManifestForBlock(int64_t blockNumber) const;

public:
	void cacheIndex();

	DataBlock readBlockHeader(int64_t blockNumber) const;
	std::string readBlockData(int64_t blockNumber, int len) const;

	int64_t getDataOffsetForBlock(int64_t blockNumber) const;

	BlockDirectories(const boost::filesystem::path &archiveRoot);
};