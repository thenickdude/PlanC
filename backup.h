#pragma once

#include <vector>
#include <utility>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/md5.h"

#include "common.h"
#include "blocks.h"

#include "boost/filesystem.hpp"

#define FILE_TYPE_INVALID          -1
#define FILE_TYPE_FILE             0
#define FILE_TYPE_DIRECTORY        1
#define FILE_TYPE_RESOURCE_WIN     2
#define FILE_TYPE_RESOURCE_MAC     3
#define FILE_TYPE_SYMLINK          4
#define FILE_TYPE_FIFO             5
#define FILE_TYPE_BLOCK_DEVICE     6
#define FILE_TYPE_CHARACTER_DEVICE 7
#define FILE_TYPE_SOCKET           8

// The strategies for storing a revision of a file (handlerId):

#define FILE_VERSION_HANDLER_DEFAULT_128  0

/* Appears to be "gzip the file first and then chunk it into uncompressed blocks" so decompression has to happen as a
 * post-process after chunk assembly:
 */
#define FILE_VERSION_HANDLER_COMPRESS_FIRST_128  1
#define FILE_VERSION_HANDLER_UNCOMPRESSED_128  2
#define FILE_VERSION_HANDLER_SYMLINK_128  2

// This is the one that my modern version of CrashPlan uses for everything:
#define FILE_VERSION_HANDLER_COMPRESSED   4
#define FILE_VERSION_HANDLER_UNCOMPRESSED 5

// Except symlinks which use this of course:
#define FILE_VERSION_HANDLER_SYMLINK      6

typedef std::vector<int64_t> BlockList;

BlockList resolveBlockList(BlockList thisList, BlockList previousList);

class SourceFileVersion {
public:
	int64_t timestamp;
	int64_t sourceLastModified;
	int64_t sourceLength;
	CryptoPP::byte sourceChecksum[CryptoPP::Weak::MD5::DIGESTSIZE];
	CryptoPP::byte fileType;

	bool isRegularFile() const {
		return fileType == FILE_TYPE_FILE;
	}

	bool isSymlink() const {
		return fileType == FILE_TYPE_SYMLINK;
	}

	bool isDirectory() const {
		return fileType == FILE_TYPE_DIRECTORY;
	}

	bool isResourceFork() const {
		return fileType == FILE_TYPE_RESOURCE_MAC || fileType == FILE_TYPE_RESOURCE_WIN;
	}

	bool isDeviceFile() const {
		return fileType >= FILE_TYPE_FIFO && fileType <= FILE_TYPE_SOCKET;
	}

	bool isDeleted() const {
		for (int i = 0 ; i < sizeof(sourceChecksum); i++) {
			if (sourceChecksum[i] != 0xFF) {
				return false;
			}
		}
		return true;
	}

	template<typename T>
	void readFrom(T &stream) {
		timestamp = readInt64BE(stream);
		sourceLastModified = readInt64BE(stream);
		sourceLength = readInt64BE(stream);
		readBytes(sourceChecksum, stream, sizeof(sourceChecksum));
		fileType = readUInt8(stream);
	}
};

class ArchivedFileVersion : public SourceFileVersion {
public:
	int16_t handlerId;
	int64_t metadataBlockNumber;
	bool hasSourceBlocksChecksum;
	CryptoPP::byte sourceBlocksChecksum[CryptoPP::Weak::MD5::DIGESTSIZE];
	BlockList blockInfo;

	template<typename T>
	void readFrom(T &stream, int dataVersion) {
		SourceFileVersion::readFrom(stream);

		handlerId = readInt16BE(stream);

		if (dataVersion >= 1) {
			metadataBlockNumber = readInt64BE(stream);
		} else {
			metadataBlockNumber = -1;
		}

		hasSourceBlocksChecksum = dataVersion >= 2;
		if (hasSourceBlocksChecksum) {
			readBytes(sourceBlocksChecksum, stream, sizeof(sourceBlocksChecksum));
		}

		int32_t blockCount = readInt32BE(stream);

		blockInfo.resize(blockCount);
		for (int32_t i = 0; i < blockCount; i++) {
			blockInfo[i] = readInt64BE(stream);
		}
	}
};

typedef class FileManifestHeader {
public:
	CryptoPP::byte fileId[CryptoPP::Weak::MD5::DIGESTSIZE];
	CryptoPP::byte parentFileId[CryptoPP::Weak::MD5::DIGESTSIZE];
	CryptoPP::byte fileType;

	SourceFileVersion version;

	int64_t fileHistoryPosition;
	int32_t fileHistoryLength;
	int16_t encPathLen;

	std::string path;

	bool hasHistory() {
		return fileHistoryPosition > -1 && fileHistoryLength > 0
			   && fileHistoryLength < std::numeric_limits<int32_t>::max();
	}
} FileManifestHeader;

class FileHistorySnapshot {
public:
	ArchivedFileVersion version;
	BlockList blockList;
};

class FileHistoryIterator {
private:
	std::vector<ArchivedFileVersion> *versions;
	int index;

	FileHistorySnapshot snapshot;

public:
	explicit FileHistoryIterator(std::vector<ArchivedFileVersion> *versions, bool end = false);
	FileHistoryIterator (const FileHistoryIterator &);
	FileHistoryIterator& operator= (const FileHistoryIterator& that);

	bool operator==(const FileHistoryIterator& that) const;
	bool operator!=(const FileHistoryIterator& that) const;

	FileHistoryIterator& operator++ ();   // pre-increment
	FileHistoryIterator operator++ (int); // post-increment

	FileHistorySnapshot& operator *();
	FileHistorySnapshot* operator ->();
};

class FileHistory {
public:
	typedef FileHistoryIterator iterator;

	CryptoPP::byte fileId[CryptoPP::Weak::MD5::DIGESTSIZE];
	CryptoPP::byte manifestChecksum[CryptoPP::Weak::MD5::DIGESTSIZE];

	std::vector<ArchivedFileVersion> versions;

	iterator begin() {
		return iterator(&versions);
	}

	iterator end() {
		return iterator(&versions, true);
	}
};

enum class FilenameMatchMode {
	none,
	prefix,
	equals
};

class BackupArchiveFileIterator {
private:
	FILE *manifestFile;
	FILE *historyFile;
	bool isEnd;

	FileManifestHeader currentFile;

	std::string key;

	FilenameMatchMode matchMode;
	std::string search;

	void findNextFile();

public:
	BackupArchiveFileIterator(FILE *manifestFile, FILE *historyFile, const std::string &key, FilenameMatchMode matchMode, const std::string &search);
	BackupArchiveFileIterator (const BackupArchiveFileIterator &);
	BackupArchiveFileIterator& operator= (const BackupArchiveFileIterator& that);
	~BackupArchiveFileIterator();

	bool operator==(const BackupArchiveFileIterator& that) const;
	bool operator!=(const BackupArchiveFileIterator& that) const;

	BackupArchiveFileIterator& operator++ ();   // pre-increment
	BackupArchiveFileIterator operator++ (int); // post-increment

	FileManifestHeader operator *();
};

class BackupArchive {
private:
	boost::filesystem::path rootPath;

	FILE *fileManifest;
	FILE *fileHistory;
	int fileHistoryHandle;

public:
	typedef BackupArchiveFileIterator iterator;

	BlockDirectories blockDirectories;

	std::string key;

	explicit BackupArchive(const boost::filesystem::path &path, const std::string &key);
	~BackupArchive();

	void cacheBlockIndex();

	// Iterate files from the file manifest
	iterator begin(FilenameMatchMode matchMode, const std::string &search);
	iterator end();

	FileHistory getFileHistory(const FileManifestHeader &manifest);
};