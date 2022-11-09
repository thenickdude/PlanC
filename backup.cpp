#define __STDC_FORMAT_MACROS
#define _POSIX_C_SOURCE 200112L
#define _FILE_OFFSET_BITS 64

#ifdef _WIN32
// lseek
#include <io.h>
#endif

#include "backup.h"

std::vector<int64_t> resolveBlockList(std::vector<int64_t> thisList, std::vector<int64_t> previousList) {
	std::vector<int64_t> resultList;

	for (int i = 0; i < thisList.size(); ) {
		int64_t thisBlock = thisList[i++];

		if (thisBlock < 0) {
			int runStartIndex = (int) -(thisBlock + 1);
			int runLength = (int) thisList[i++];

			// Copy a run of block indexes from the previous revision's list of blocks
			for (int j = 0; j < runLength; j++) {
				resultList.push_back(previousList[runStartIndex + j]);
			}
		} else {
			resultList.push_back(thisBlock);
		}
	}

	return resultList;
}

BackupArchive::BackupArchive(const boost::filesystem::path &path, const std::string &key) : rootPath(path), blockDirectories(path), key(key) {
	fileManifestFilename = (path / boost::filesystem::path("cpfmf")).string();
	fileHistoryFilename = (path/ boost::filesystem::path("cphdf")).string();

	fileManifest = fopen(fileManifestFilename.c_str(), "rb");
	fileHistory = fopen(fileHistoryFilename.c_str(), "rb");

	if (!fileManifest) {
		throw std::runtime_error("Failed to open file manifest file '" + fileManifestFilename + "'");
	}

	if (!fileHistory) {
		throw std::runtime_error("Failed to open file history file '" + fileHistoryFilename + "'");
	}

	fileHistoryHandle = fileno(fileHistory);
}

BackupArchive::~BackupArchive() {
	fclose(fileManifest);
	fclose(fileHistory);
}

void BackupArchive::cacheBlockIndex() {
	blockDirectories.cacheIndex();
}

void readFileManifestHeader(FILE *file, FileManifestHeader &header) {
	readBytes(header.fileId, file, sizeof(header.fileId));
	readBytes(header.parentFileId, file, sizeof(header.parentFileId));
	header.fileType = readUInt8(file);

	header.version.readFrom(file);

	header.fileHistoryPosition = readInt64BE(file);
	header.fileHistoryLength = readInt32BE(file);
	header.encPathLen = readInt16BE(file);

	// If we've already slammed into the end of the file then encPathLen is garbage, don't use it
	if (!feof(file)) {
		header.path.resize(header.encPathLen);
		readBytes((uint8_t *) &header.path[0], file, header.encPathLen);
	}
}

std::string decryptEncryptedPath(std::string path, const std::string &key) {
	const int MODERN_HEADER_LEN = 6;
	
	if (path.length() >= MODERN_HEADER_LEN) {
		uint8_t *bytes = (uint8_t *) path.data();

		int32_t magic = readInt32BE(bytes);
		uint8_t version = readUInt8(bytes);
		uint8_t encryption = readUInt8(bytes);

		if (magic == -420042000 && version == 1) {
			path = path.substr(MODERN_HEADER_LEN);

			if (encryption < CIPHER_CODE_MIN || encryption > CIPHER_CODE_MAX) {
				throw std::runtime_error("Unsupported filename cipher " + std::to_string(encryption));
			} else {
				return code42Ciphers[encryption]->decrypt(path, key);
			}
		}
	}
	
	// Assume this the older headerless format that just hard-coded the use of Blowfish-128
	return code42Ciphers[CIPHER_CODE_BLOWFISH_128]->decrypt(path, key);
}

BackupArchive::iterator BackupArchive::begin(FilenameMatchMode matchMode, const std::string &search) {
	return BackupArchive::iterator(fileManifestFilename, key, matchMode, search);
}

BackupArchive::iterator BackupArchive::end() {
	return BackupArchive::iterator(fileManifestFilename);
}

FileHistory BackupArchive::getFileHistory(const FileManifestHeader &manifest) {
	FileHistory result;

	lseek(fileHistoryHandle, manifest.fileHistoryPosition, SEEK_SET);

	// Read the whole compressed history into a buffer:
	size_t bytesToRead = manifest.fileHistoryLength;
	std::string compressedHistory(bytesToRead, '\0');

	while (bytesToRead > 0) {
		ssize_t bytesRead = read(fileHistoryHandle, &compressedHistory[0], bytesToRead);

		if (bytesRead >= 0) {
			bytesToRead -= bytesRead;

			if (bytesRead == 0 && bytesToRead > 0) {
				throw std::runtime_error("Unexpected end of file when reading file history");
			}
		}
	}

	// History may or may not be compressed (gzip/zlib), auto-detect that and decompress it if needed:
	std::string historyBuffer = maybeDecompress(compressedHistory);

	// Now we can use these cursors to walk the uncompressed history data:
	uint8_t *historyCursor = (uint8_t *) historyBuffer.data();
	uint8_t *historyEnd = historyCursor + historyBuffer.length();

	int16_t magic = readInt16BE(historyCursor);
	int16_t dataVersion;

	if (magic == 4242) {
		dataVersion = readInt16BE(historyCursor);
	} else {
		historyCursor -= 2; // Unread that magic value.

		/* Interestingly it looks like the subsequent MD5 field in version 0 files could be
		 * occasionally (1/65536) misinterpreted as a magic value
		 */

		dataVersion = 0;
	}

	readBytes(result.fileId, historyCursor, sizeof(result.fileId));

	if (dataVersion >= 2) {
		readBytes(result.manifestChecksum, historyCursor, sizeof(result.manifestChecksum));
	}

	if (memcmp(result.fileId, manifest.fileId, sizeof(manifest.fileId)) != 0) {
		throw std::runtime_error("Bad revision history pointer for file, can't fetch revisions");
	}

	while (historyCursor < historyEnd) {
		ArchivedFileVersion fileVersion;

		fileVersion.readFrom(historyCursor, dataVersion);

		result.versions.push_back(fileVersion);
	}

	return result;
}

BackupArchiveFileIterator::BackupArchiveFileIterator(const std::string &manifestFilename) :
	fileManifestFilename(manifestFilename),
	isEnd(true)
{
}

BackupArchiveFileIterator::BackupArchiveFileIterator(const std::string &manifestFilename,
						  const std::string &key, FilenameMatchMode matchMode, const std::string &search) :
		fileManifestFilename(manifestFilename),
		isEnd(false),
		key(key),
		matchMode(matchMode), search(search) {

	openFileManifest();

	// Advance to the first file
	findNextFile();
}

void BackupArchiveFileIterator::findNextFile() {
	if (!isEnd) {
		bool found;

		do {
		    off_t start = ftello(manifestFile);
		    
			readFileManifestHeader(manifestFile, currentFile);

			if (feof(manifestFile)) {
				isEnd = true;
				fclose(manifestFile);
				break;
			}
			
			try {
                currentFile.path = decryptEncryptedPath(currentFile.path, key);
            } catch (const std::exception &e) {
			    std::cerr << "Failed to decrypt path for file at offset " << std::to_string(start) << std::endl;
			    throw;
			}

			// Does this path meet our search conditions?
			switch (matchMode) {
				case FilenameMatchMode::none:
					found = true;
					break;
				case FilenameMatchMode::prefix:
					found = currentFile.path.find(search) == 0;
					break;
				case FilenameMatchMode::equals:
					found = currentFile.path == search;
					break;
			}
		} while (!found);
	}
}

FileManifestHeader BackupArchiveFileIterator::operator*() {
	return currentFile;
}

bool BackupArchiveFileIterator::operator==(const BackupArchiveFileIterator &that) const {
	if (isEnd != that.isEnd) {
		return false;
	}

	if (fileManifestFilename != that.fileManifestFilename) {
		return false;
	}

	if (isEnd && that.isEnd) {
		return true;
	}

	return ftello(manifestFile) == ftello(that.manifestFile);
}

bool BackupArchiveFileIterator::operator!=(const BackupArchiveFileIterator &that) const {
	return !(*this == that);
}

BackupArchiveFileIterator &BackupArchiveFileIterator::operator++() {
	findNextFile();

	return *this;
}

BackupArchiveFileIterator BackupArchiveFileIterator::operator++(int) {
	BackupArchiveFileIterator temp(*this);

	++*this;

	return temp;
}

void BackupArchiveFileIterator::openFileManifest() {
	if (!isEnd) {
		manifestFile = fopen(fileManifestFilename.c_str(), "rb");

		if (!manifestFile) {
			throw std::runtime_error(
				"Failed to open archive file manifest " + fileManifestFilename);
		}
	}
}

BackupArchiveFileIterator::BackupArchiveFileIterator(const BackupArchiveFileIterator & that) :
		fileManifestFilename(that.fileManifestFilename),
		isEnd(that.isEnd),
		key(that.key),
		matchMode(that.matchMode), search(that.search) {

	openFileManifest();

	// Doesn't advance the pointer
}

BackupArchiveFileIterator &BackupArchiveFileIterator::operator=(const BackupArchiveFileIterator &that) {
	if (!isEnd) {
		fclose(manifestFile);
	}

	fileManifestFilename = that.fileManifestFilename;
	isEnd = that.isEnd;

	openFileManifest();

	currentFile = that.currentFile;

	key = that.key;
	matchMode = that.matchMode;
	search = that.search;

	return *this;
}

BackupArchiveFileIterator::~BackupArchiveFileIterator() {
	if (!isEnd) {
		fclose(manifestFile);
	}
}

FileHistoryIterator::FileHistoryIterator(std::vector<ArchivedFileVersion> *versions, bool end) : versions(versions), index(end ? versions->size() : 0) {
	if (index == 0 && !versions->empty()) {
		snapshot.version = (*versions)[0];
		snapshot.blockList = resolveBlockList(snapshot.version.blockInfo, snapshot.version.blockInfo);
	}
}

FileHistorySnapshot& FileHistoryIterator::operator*() {
	return snapshot;
}

FileHistorySnapshot* FileHistoryIterator::operator->() {
	return &snapshot;
}

bool FileHistoryIterator::operator==(const FileHistoryIterator &that) const {
	return index == that.index;
}

bool FileHistoryIterator::operator!=(const FileHistoryIterator &that) const {
	return index != that.index;
}

FileHistoryIterator &FileHistoryIterator::operator++() {
	index++;

	if (index < versions->size()) {
		snapshot.version = (*versions)[index];
		// Resolve backreferences in the list of block numbers using the previous revision we pointed to:
		snapshot.blockList = resolveBlockList(snapshot.version.blockInfo, snapshot.blockList);
	}

	return *this;
}

FileHistoryIterator FileHistoryIterator::operator++(int) {
	FileHistoryIterator temp(*this);

	++*this;

	return temp;
}

FileHistoryIterator::FileHistoryIterator(const FileHistoryIterator & that) :
	versions(that.versions),
	index(that.index),
	snapshot(that.snapshot) {
}

FileHistoryIterator &FileHistoryIterator::operator=(const FileHistoryIterator &that) {
	versions = that.versions;
	index = that.index;
	snapshot = that.snapshot;

	return *this;
}