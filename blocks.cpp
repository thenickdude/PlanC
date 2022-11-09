#define __STDC_FORMAT_MACROS
#define _POSIX_C_SOURCE 200112L
#define _FILE_OFFSET_BITS 64

#include <iostream>

#include <cstdlib>
#include <cstdio>
#include <errno.h>

#ifdef _WIN32
// lseek
#include <io.h>
#endif

#include "boost/filesystem/operations.hpp"
#include "boost/range/iterator_range.hpp"

#include "blocks.h"
#include "common.h"

const char *BLOCK_FOLDER_NAME_PREFIX = "cpbf";
const int BLOCK_FOLDER_NAME_DIGITS = 19;

const int BLOCK_MANIFEST_HEADER_SIZE = 256;
const int BLOCK_MANIFEST_RECORD_SIZE = 9;

const int BLOCK_DATA_FILE_HEADER_LEN = 256;
const int BLOCK_DATA_HEADER_LEN = 53;

static bool isValidBlockDirectoryName(const std::string & filename) {
	if (filename.length() != strlen(BLOCK_FOLDER_NAME_PREFIX) + BLOCK_FOLDER_NAME_DIGITS || filename.find(BLOCK_FOLDER_NAME_PREFIX) != 0) {
		return false;
	}

	for (int i = 0; i < BLOCK_FOLDER_NAME_DIGITS; i++) {
		char c = filename[i + strlen(BLOCK_FOLDER_NAME_PREFIX)];

		if (!(c >= '0' && c <= '9')) {
			return false;
		}
	}

	return true;
}

bool BlockManifest::containsBlock(int64_t blockNumber) const {
	blockNumber -= firstBlockNum;

	if (blockNumber < 0 || blockNumber >= entries.size()) {
		return false;
	}

	return entries[blockNumber].isValid();
}

/**
 * Get the offset of the block's header in the block data file.
 *
 * @param blockNumber
 * @return
 */
int64_t BlockManifest::getDataOffsetForBlock(int64_t blockNumber) const {
	blockNumber -= firstBlockNum;

	if (blockNumber < 0 || blockNumber >= entries.size()) {
		throw std::runtime_error("Attempted to get offset for block that doesn't belong to this manifest");
	}

	return entries[blockNumber].offset;
}

void BlockManifest::open() {
	entries.clear();

	boost::filesystem::path manifestPath = directoryPath / boost::filesystem::path("cpbmf");
	boost::filesystem::path dataPath = directoryPath / boost::filesystem::path("cpbdf");

	FILE *manifestFile = fopen(manifestPath.string().c_str(), "rb");

	if (!manifestFile) {
		throw std::runtime_error("Failed to open block manifest (" + manifestPath.string() + ") for reading: " + strerror(errno));
	}

	fseek(manifestFile, 0, SEEK_END);
	long manifestLength = ftell(manifestFile);
	fseek(manifestFile, BLOCK_MANIFEST_HEADER_SIZE, SEEK_SET);

	entries.resize((manifestLength - BLOCK_MANIFEST_HEADER_SIZE) / BLOCK_MANIFEST_RECORD_SIZE);

	for (int i = 0; i < entries.size(); i++) {
		entries[i].offset = readInt64BE(manifestFile);
		entries[i].state = readInt8(manifestFile);
	}

	if (feof(manifestFile)) {
		throw std::runtime_error("Unexpected end of file when reading: " + manifestPath.string());
	}

	fclose(manifestFile);

	// And open the block data file for later reading...
	blockData = fopen(dataPath.string().c_str(), "rb");

	if (!blockData) {
		throw std::runtime_error("Failed to open block data file (" + dataPath.string() + ") for reading: " + strerror(errno));
	}

	blockDataHandle = fileno(blockData);
}

const BlockManifest& BlockDirectories::getManifestForBlock(int64_t blockNumber) const {
	int i;

	for (i = 0; i < directories.size(); i++) {
		if (blockNumber < directories[i].firstBlockNum) {
			break;
		}
	}

	return i > 0 ? directories[i - 1] : directories[0];
}

std::string BlockManifest::readBlockData(int64_t blockNumber, int len) const {
	int64_t fileOffset = getDataOffsetForBlock(blockNumber);

	if (fileOffset < BLOCK_DATA_FILE_HEADER_LEN) {
		throw std::runtime_error("Attempted to read a block at impossible offset");
	}

	lseek(blockDataHandle, fileOffset + BLOCK_DATA_HEADER_LEN, SEEK_SET);

	std::string result;

	result.resize(len);

	// TODO retry loop
	read(blockDataHandle, &result[0], len);

	return result;
}

DataBlock BlockManifest::readBlockHeader(int64_t blockNumber) const {
	int64_t fileOffset = getDataOffsetForBlock(blockNumber);

	if (fileOffset < BLOCK_DATA_FILE_HEADER_LEN) {
		throw std::runtime_error("Attempted to read a block at impossible offset");
	}

	lseek(blockDataHandle, fileOffset, SEEK_SET);

	uint8_t buffer[BLOCK_DATA_HEADER_LEN];
	uint8_t *cursor = buffer;

	// TODO retry loop
	read(blockDataHandle, buffer, sizeof(buffer));

	DataBlock result;

	result.readFrom(cursor);

	if (result.blockNum != blockNumber) {
		throw std::runtime_error("Block in datafile's ID differs from the ID requested (bad block pointer in index)");
	}

	return result;
}

int64_t BlockDirectories::getDataOffsetForBlock(int64_t blockNumber) const {
	return getManifestForBlock(blockNumber).getDataOffsetForBlock(blockNumber);
}

DataBlock BlockDirectories::readBlockHeader(int64_t blockNumber) const {
	const BlockManifest &manifest = getManifestForBlock(blockNumber);

	return manifest.readBlockHeader(blockNumber);
}

std::string BlockDirectories::readBlockData(int64_t blockNumber, int len) const {
	const BlockManifest &manifest = getManifestForBlock(blockNumber);

	return manifest.readBlockData(blockNumber, len);
}

BlockDirectories::BlockDirectories(const boost::filesystem::path &archiveRoot) : rootPath(archiveRoot) {
	if (!boost::filesystem::is_directory(archiveRoot)) {
		throw std::runtime_error("Bad BlockDirectories path " + archiveRoot.string());
	}

	// Find all the valid-looking cpbf directories in the archive:
	for(auto& entry : boost::make_iterator_range(boost::filesystem::directory_iterator(rootPath), {})) {
		std::string filename = entry.path().filename().string();

		if (isValidBlockDirectoryName(filename) && boost::filesystem::is_directory(entry.path())) {
			boost::filesystem::path cpbdfPath = entry.path() / boost::filesystem::path("cpbdf");
			boost::filesystem::path cpbmfPath = entry.path() / boost::filesystem::path("cpbmf");

			if (boost::filesystem::is_regular_file(cpbdfPath) && boost::filesystem::is_regular_file(cpbmfPath)) {
				directories.emplace_back(BlockManifest(
					entry.path(),
					strtoull(filename.c_str() + strlen(BLOCK_FOLDER_NAME_PREFIX), nullptr, 10)
				));
			}
		}
	}

	std::sort(directories.begin(), directories.end());
}

void BlockDirectories::cacheIndex() {
	for (auto &directory : directories) {
		directory.open();
	}
}