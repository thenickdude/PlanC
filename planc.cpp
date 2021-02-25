#define __STDC_FORMAT_MACROS
#define _FILE_OFFSET_BITS 64

#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <ctype.h>
#include <sstream>
#include <thread>
#include <atomic>

#include "zstr/src/zstr.hpp"

#include "leveldb/db.h"

#include "boost/algorithm/hex.hpp"
#include "boost/asio/post.hpp"
#include "boost/asio/thread_pool.hpp"
#include "boost/program_options.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/iostreams/stream.hpp"
#include "boost/iostreams/device/null.hpp"
#include "boost/iostreams/filtering_streambuf.hpp"
#include "boost/iostreams/copy.hpp"
#include "boost/iostreams/filter/gzip.hpp"
#include "boost/date_time.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptopp/md5.h"
#include "cryptopp/sha.h"
#include "cryptopp/channels.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

#include "common.h"
#include "backup.h"
#include "adb.h"
#include "properties.h"

using namespace CryptoPP;
using namespace std;
namespace po = boost::program_options;

std::string formatDateTime(time_t time, const std::string &format) {
	boost::posix_time::time_facet *facet = new boost::posix_time::time_facet();
	boost::posix_time::ptime p = boost::posix_time::from_time_t(time);

	std::stringstream stream;

	facet->format(format.c_str());
	// std::locale is responsible for destroying the facet:
	stream.imbue(std::locale(std::locale::classic(), facet));
	stream << p;

	return stream.str();
}

time_t parseDateTime(const std::string &time) {
	return boost::posix_time::to_time_t(boost::posix_time::ptime(boost::posix_time::time_from_string(time)));
}

time_t archiveTimestampToUnix(time_t time) {
	return time / 1000;
}

void printFileRevision(const FileManifestHeader &file, const ArchivedFileVersion &version) {
	time_t revisionTimestamp = archiveTimestampToUnix(version.timestamp);
	string revisionTime = formatDateTime(revisionTimestamp, "%Y-%m-%d %H:%M:%S");
	time_t lastModifiedTimestamp = archiveTimestampToUnix(version.sourceLastModified);
	string lastModifiedTime = formatDateTime(lastModifiedTimestamp, "%Y-%m-%d %H:%M:%S");
	string checksum;

	if (version.isDeleted()) {
		checksum = "X";
	} else if (version.isDirectory()) {
		checksum = "-";
	} else {
		checksum = binStringToHex(string((char *) version.sourceChecksum, sizeof(version.sourceChecksum)));
	}

	printf("%.*s %" PRId64 " %.*s %.*s %.*s\n",
		   (int) file.path.length(), file.path.data(),
		   version.sourceLength,
		   (int) revisionTime.length(), revisionTime.data(),
		   (int) lastModifiedTime.length(), lastModifiedTime.data(),
		   (int) checksum.length(),
		   checksum.data()
	);
}

enum class FileListDetailLevel {
	basic, detailed
};

enum class TimeMode {
	latest,
	atTime,
	all
};

void listBackupFiles(BackupArchive &archive, BackupArchive::iterator &begin, BackupArchive::iterator &end,
					 FileListDetailLevel detailLevel, bool includeDeleted, TimeMode timeMode, time_t atTime) {
	while (begin != end) {
		FileManifestHeader file = *begin;
		++begin;

		if (detailLevel == FileListDetailLevel::basic) {
			// Just printing all filenames, we don't even need to fetch the history to see if the file was deleted or not
			printf(
				"%.*s\n",
				(int) file.path.length(), file.path.data()
			);
		} else if (file.hasHistory()) {
			FileHistory fileHistory = archive.getFileHistory(file);

			if (!fileHistory.versions.empty()) {
				int i;

				switch (timeMode) {
					case TimeMode::all:
						for (auto & revision : fileHistory.versions) {
							printFileRevision(file, revision);
						}
						break;
					case TimeMode::latest:
						if (includeDeleted || !fileHistory.versions.back().isDeleted()) {
							printFileRevision(file, fileHistory.versions.back());
						}
						break;

					case TimeMode::atTime:
						for (i = 0; i < fileHistory.versions.size(); i++) {
							if (archiveTimestampToUnix(fileHistory.versions[i].timestamp) > atTime) {
								// This snapshot is newer than the one we want to see
								break;
							}
						}

						if (i > 0 && (includeDeleted || !fileHistory.versions[i - 1].isDeleted())) {
							printFileRevision(file, fileHistory.versions[i - 1]);
						}

						break;
				}
			}
		} else {
			// Not sure why this would happen unless database is corrupt (special files-that-arent-files as flags?)
			cerr << "Error: No revision history found for '" << file.path << "'" << endl;
		}
	}
}

void readFileRevisionData(const BackupArchive &archive,
						  const FileManifestHeader &file, const ArchivedFileVersion &version,
						  const vector<int64_t> &blockList,
						  CryptoPP::BufferedTransformation &output) {
	CryptoPP::Weak::MD5 hasher;

	bool hasCorruptBlocks = false;

	for (int64_t blockNumber : blockList) {
		DataBlock block = archive.blockDirectories.readBlockHeader(blockNumber);
		std::string archivedData = archive.blockDirectories.readBlockData(blockNumber, block.backupLen);

		std::string decryptedData;

		uint8_t cipher = block.getCipher();

		if (block.isEncrypted() || block.isCompressed()) {
			// Check that the archived block isn't corrupt before we try something interesting like decryption or decompression

			CryptoPP::byte archivedHash[CryptoPP::Weak::MD5::DIGESTSIZE];
			hasher.Update((const CryptoPP::byte*) archivedData.data(), archivedData.length());
			hasher.Final(archivedHash);

			if (memcmp(archivedHash, block.backupMD5, sizeof(archivedHash)) != 0) {
				/*
				 * Since we daren't decrypt or decompress this block, replace its position in the file with a string
				 * of nul bytes of the same original length:
				 */
				int bytesToPad = block.sourceLen;
				const int PADDING_BUFFER_SIZE = 16 * 1024;
				auto padding = new uint8_t[PADDING_BUFFER_SIZE](); // Zero-initialised by the ()

				while (bytesToPad > 0) {
					int padThisLoop = bytesToPad < PADDING_BUFFER_SIZE ? bytesToPad : PADDING_BUFFER_SIZE;

					output.Put((const CryptoPP::byte *) padding, padThisLoop);

					bytesToPad -= padThisLoop;
				}

				delete [] padding;

				hasCorruptBlocks = true;

				continue;
			}
		}

		retryDecrypt:

		if (block.isEncrypted() && isValidCipherCode(cipher)) {
			try {
				archivedData = code42Ciphers[cipher]->decrypt(archivedData, archive.key);
			} catch (BadPaddingException & e) {
				if (cipher == CIPHER_CODE_BLOWFISH_448) {
					cipher = CIPHER_CODE_BLOWFISH_128;
					goto retryDecrypt;
				}
				throw;
			}
		}

		if (block.isCompressed()) {
			try {
				archivedData = maybeDecompress(archivedData);
			} catch (std::exception & e) {
				if (block.type != DATA_BLOCK_TYPE_UNKNOWN) {
					throw;
				}

				/* If the "compressed" MD5 is the same as the source MD5, it was never compressed in the first
				 * place and we can just pass it through.
				 */
				CryptoPP::byte compressedHash[CryptoPP::Weak::MD5::DIGESTSIZE];
				hasher.Update((const CryptoPP::byte*) archivedData.data(), archivedData.length());
				hasher.Final(compressedHash);

				if (memcmp(compressedHash, block.sourceMD5, sizeof(compressedHash)) != 0) {
					throw;
				}
			}
		}

		// Check that the hash of the restored block is the same as what it was raw on disk when first backed up
		CryptoPP::byte restoredHash[CryptoPP::Weak::MD5::DIGESTSIZE];
		hasher.Update((const CryptoPP::byte*) archivedData.data(), archivedData.length());
		hasher.Final(restoredHash);

		if (memcmp(restoredHash, block.sourceMD5, sizeof(restoredHash)) != 0) {
			hasCorruptBlocks = true;
		}

		// Finally write it to the destination
		output.Put((const CryptoPP::byte *) archivedData.data(), archivedData.length());
	}

	if (hasCorruptBlocks) {
		throw std::runtime_error("Some blocks in this file did not restore correctly (bad MD5)");
	}
}

void restoreFileRevision(const BackupArchive &archive,
						 const FileManifestHeader &file, const ArchivedFileVersion &version,
						 const BlockList &blockList,
						 const boost::filesystem::path &destDirectory,
						 bool dryRun = true) {
	boost::filesystem::path destFilename = destDirectory / boost::filesystem::path(file.path);

	if (!dryRun) {
		boost::filesystem::create_directories(destFilename.parent_path());
	}

	if (version.isRegularFile()) {
		std::string tempFilename = destFilename.string() + "._planc_temp";

		std::string fileMD5;
		CryptoPP::Weak::MD5 md5Hasher;
		CryptoPP::HashFilter hashFilter(md5Hasher, new CryptoPP::StringSink(fileMD5));

		CryptoPP::FileSink *outputSink = nullptr;

		CryptoPP::ChannelSwitch cs;

		// The restored file is hashed as it is decoded:
		cs.AddDefaultRoute(hashFilter);

		// And written to a file if this isn't a dry run:
		if (!dryRun) {
			outputSink = new CryptoPP::FileSink(tempFilename.c_str(), true);
			cs.AddDefaultRoute(*outputSink);
		}

		// Do the restore now:
		readFileRevisionData(archive, file, version, blockList, cs);

		cs.MessageEnd();

		if (!dryRun) {
			delete outputSink;
		}

		// Now we need to turn that temporary file into the destination file:

		switch (version.handlerId) {
			case FILE_VERSION_HANDLER_COMPRESS_FIRST_128: {
				if (dryRun) {
					throw std::runtime_error("Dry run not implemented for this filetype");
				}

				// Decompress the temp file using bzip

				// Note I've never tested this path since this format appears to be deprecated (my client doesn't generate it)

				ifstream inFile(tempFilename, ios_base::in | ios_base::binary);
				ofstream outFile(destFilename.string(), std::ofstream::binary | std::ofstream::trunc);

				boost::iostreams::filtering_streambuf<boost::iostreams::input> inFilters;
				inFilters.push(boost::iostreams::gzip_decompressor());
				inFilters.push(inFile);

				boost::iostreams::copy(inFilters, outFile);

				outFile.close();

				fileMD5 = "";

				FileSource fs(tempFilename.c_str(), true /* PumpAll */,
				   new HashFilter(md5Hasher, new StringSink(fileMD5))
				);

				if (memcmp(fileMD5.data(), version.sourceChecksum, sizeof(version.sourceChecksum)) != 0) {
					throw std::runtime_error("MD5 of restored file is incorrect!");
				}
			}
			break;
			default:
				if (memcmp(fileMD5.data(), version.sourceChecksum, sizeof(version.sourceChecksum)) != 0) {
					throw std::runtime_error("MD5 of restored file is incorrect!");
				}

				if (!dryRun) {
					boost::filesystem::rename(boost::filesystem::path(tempFilename), destFilename);
				}
		}
	} else if (version.isSymlink()) {
		std::string symlinkContents;
		StringSink sink(symlinkContents);

		readFileRevisionData(archive, file, version, blockList, sink);

		if (!dryRun) {
			try {
				boost::filesystem::create_symlink(boost::filesystem::path(symlinkContents), destFilename);
			} catch (boost::filesystem::filesystem_error &e) {
				throw std::runtime_error(
					"Failed to create symlink to " + symlinkContents + " at " + destFilename.string() + ": "
					    + e.what());
			}
		}
	} else if (version.isDirectory()) {
		if (!dryRun) {
			try {
				boost::filesystem::create_directory(destFilename);
			} catch (boost::filesystem::filesystem_error &e) {
				throw std::runtime_error(
					"Failed to create output directory " + destFilename.string() + ": " + e.what());
			}
		}
	} else {
		throw std::runtime_error("Unsupported filetype " + std::to_string(version.fileType) + " for restore of '" + file.path + "', is this a device file or resource fork?");
	}

	if (!dryRun) {
		try {
			boost::filesystem::last_write_time(destFilename, archiveTimestampToUnix(version.sourceLastModified));
		} catch (boost::filesystem::filesystem_error &e) {
			std::cerr << "Failed to update timestamp of '" << destFilename.string() << "': " << e.what() << std::endl;
		}
	}

	// Successfully restored this file
	cout << file.path << endl;
}

bool restoreBackupFiles(BackupArchive &archive, BackupArchive::iterator &begin, BackupArchive::iterator &end,
						const boost::filesystem::path &destDirectory,
						bool includeDeleted, TimeMode timeMode, time_t atTime,
						bool dryRun = true) {
	bool success = true;

	// For every matched file in the manifest:
	while (begin != end) {
		FileManifestHeader file = *begin;
		++begin;

		if (file.hasHistory()) {
			try {
				FileHistory fileHistory = archive.getFileHistory(file);

				FileHistorySnapshot previous;
				FileHistorySnapshot previousNotDeleted;
				bool hasPrevious = false;
				bool hasPreviousNotDeleted = false;

				// Locate the revision we want to restore:
				for (auto iterator = fileHistory.begin(); iterator != fileHistory.end(); ++iterator) {
					if (timeMode == TimeMode::atTime && archiveTimestampToUnix(iterator->version.timestamp) > atTime) {
						break;
					}

					previous = *iterator;
					hasPrevious = true;

					if (!iterator->version.isDeleted()) {
						previousNotDeleted = *iterator;
						hasPreviousNotDeleted = true;
					}
				}

				if (includeDeleted && hasPreviousNotDeleted) {
					restoreFileRevision(archive, file, previousNotDeleted.version, previousNotDeleted.blockList, destDirectory, dryRun);
				} else if (hasPrevious && !previous.version.isDeleted()) {
					restoreFileRevision(archive, file, previous.version, previous.blockList, destDirectory, dryRun);
				}
			} catch (std::exception &e) {
				success = false;
				cerr << "Error: Failures occurred while restoring '" << file.path << "': " << e.what() << endl;
			}
		} else {
			// Not sure why this would happen unless database is corrupt (special files-that-aren't-files as flags?)
			success = false;
			cerr << "Error: No revision history found for '" << file.path << "'" << endl;
		}
	}

	return success;
}

std::string readInputLine() {
	char buffer[1024];
	char *newLine;

	fgets(buffer, sizeof(buffer), stdin);

	if ((newLine = strchr(buffer, '\r'))
		|| (newLine = strchr(buffer, '\n'))) {
		*newLine = '\0';
	}

	return std::string(buffer);
}

std::string recoverADBKey(leveldb::DB *adb) {
	std::string keyType;

    try {
        keyType = adbReadKey(adb, "\x01" "ArchiveSecurityKeyType");
    } catch (const std::runtime_error &e) {
        keyType = "AccountPassword";
    }

    try {
        std::string key = adbReadKey(adb, "\x01" "ArchiveDataKey");

        if (key.length() == 0) {
            throw std::runtime_error("Read key was empty");
        }

        return key;
    } catch (std::runtime_error &e) {
        cerr << "Failed to read ArchiveDataKey from ADB: " << e.what() << endl;

        if (adbKeyExists(adb, "\x01" "ArchiveSecureDataKey")) {
            cerr << endl
                 << "It looks like there is an ArchiveSecureDataKey available instead, which is encrypted with "
                    "your CrashPlan Account Password or Archive Password. Enter that password now to attempt decryption "
                    "of the key:" << endl;

            cerr << "? ";

            string accountPassword(readInputLine());

            try {
                std::string key = adbReadSecureKey(adb, "\x01" "ArchiveSecureDataKey", accountPassword);

                return key;
            } catch (std::runtime_error &e) {
                cerr << "Failed to read ArchiveSecureDataKey from ADB: " << e.what() << endl;
                throw;
            }
        } else {
            throw;
        }
    }
}

std::string recoverCPPropertiesKey(const std::string &filename) {
    ifstream inFile(filename, ios_base::in | ios_base::binary);

    std::string propertyFile = readStreamAsString(inFile);

    std::string secureDataKey = propertiesReadField(propertyFile, "secureDataKey");

    if (secureDataKey.length() == 0) {
        throw std::runtime_error(
            "Failed to read secureDataKey field from cp.properties file, does it actually contain a field with that name?");
    }
    
    secureDataKey = base64Decode(secureDataKey);

    cerr << "The secureDataKey field in cp.properties is encrypted with your CrashPlan Account Password or Archive Password. Enter that password now to attempt decryption "
            "of the key:" << endl;

    cerr << "? ";

    std::string password(readInputLine());
    
    if (!passwordUnlocksSecureDataKey(secureDataKey, password)) {
        throw std::runtime_error("The provided password couldn't decrypt the secureDataKey, is the password correct?");
    }
    
    return decryptSecureDataKey(secureDataKey, password);
}

std::string deriveKeyFromPasswordPrompt(std::string cpProperties) {
    cerr << "Enter your Crashplan user ID (a number, can be found in conf/my.service.xml or in log files, grep for \"userId\"), or press enter if you don't know it:" << endl;

    cerr << "? ";

    const std::string userID(readInputLine());

    if (userID.length() == 0) {
        cerr << "Since you didn't provide a userid, it will be recovered using a brute-force search instead" << endl;

        if (cpProperties.length() == 0) {
            cerr
                << "You must supply a --cpproperties argument which points to the cp.properties file in your backup archive"
                << endl;
            exit(EXIT_FAILURE);
        }
    }
    
    cerr << endl
         << "Enter your passphrase:" << endl;

    cerr << "? ";

    const std::string customPassword(readInputLine());

    cerr << endl;
    
    if (userID.length() > 0) {
        return deriveCustomArchiveKeyV2(userID, customPassword);
    }
    
    ifstream inFile(cpProperties, ios_base::in | ios_base::binary);
    std::string propertyFile = readStreamAsString(inFile);
    std::string dataKeyChecksumStr = propertiesReadField(propertyFile, "dataKeyChecksum");
    CryptoPP::byte dataKeyChecksum[CryptoPP::Weak::MD5::DIGESTSIZE];
    
    if (dataKeyChecksumStr.length() == 0) {
        throw std::runtime_error(
            "Failed to read dataKeyChecksum field from cp.properties file, does it actually contain a field with that name?");
    }
    
    if (dataKeyChecksumStr.length() != sizeof(dataKeyChecksum) * 2) {
        throw std::runtime_error(
            "Expected dataKeyChecksum to be " + std::to_string(sizeof(dataKeyChecksum)) + " characters, " + std::to_string(dataKeyChecksumStr.length()) + " found");
    }
    
    boost::algorithm::unhex(dataKeyChecksumStr, dataKeyChecksum);
    
    std::cerr << "Brute-forcing your userID now (up to a maximum of #100,000)... expect this to take up to 5-10 minutes" << std::endl;
    
    boost::asio::thread_pool pool;

    const int CHUNK_SIZE = 50;
    std::atomic<int> recoveredUserID(0);
    
    for (int chunkStart = 1; chunkStart < 100000; chunkStart += CHUNK_SIZE) {
        boost::asio::post(pool, [chunkStart, customPassword, dataKeyChecksum, &recoveredUserID]() {
            for (int userID = chunkStart; userID < chunkStart + CHUNK_SIZE; userID++) {
                if (recoveredUserID.load() != 0) {
                    // Another thread already found the prize
                    break;
                }
                
                std::string userIDString = std::to_string(userID);

                std::string key = deriveCustomArchiveKeyV2(userIDString, customPassword);

                CryptoPP::Weak::MD5 hasher;
                CryptoPP::byte currentHash[CryptoPP::Weak::MD5::DIGESTSIZE];

                hasher.Update((const CryptoPP::byte *) key.data(), key.length());
                hasher.Final(currentHash);

                bool found = true;

                for (int i = 0; i < sizeof(currentHash); i++) {
                    if (currentHash[i] != dataKeyChecksum[i]) {
                        found = false;
                        break;
                    }
                }
                
                if (found) {
                    recoveredUserID.store(userID);
                    break;
                }
            }
        });
    }
    
    pool.join();
    
    if (recoveredUserID.load() == 0) {
        cerr << "Failed to brute-force userID, password is probably incorrect" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    cout << "Recovered user ID: " << std::to_string(recoveredUserID.load()) << std::endl;

    return deriveCustomArchiveKeyV2(std::to_string(recoveredUserID.load()), customPassword);
}

int main(int argc, char **argv) {
	po::options_description mainOptions("Options");
	mainOptions.add_options()
		("help", "shows this page")
		("adb", po::value<string>(),
		 "path to CrashPlan's 'adb' directory to recover a decryption key from (e.g. /Library/Application Support/CrashPlan/conf/adb. Optional)")
        ("cpproperties", po::value<string>(),
            "path to a cp.properties file containing a 'secureDataKey' field to recover a decryption key from (Optional)")
		("key", po::value<string>(), "your backup decryption key (Hexadecimal, not your password. Optional)")
        ("key64", po::value<string>(), "backup decryption key in base64 (76 characters long. Optional)")
		("archive", po::value<string>(), "the root of your CrashPlan backup archive")

		("command", po::value<string>(), "command to run (recover-key,list,restore,etc)")
		;

	po::options_description filterOptions("Which archived files to operate on");
	filterOptions.add_options()
		("prefix", po::value<string>(), "prefix of the archived filepath to operate on")
		("filename", po::value<string>(), "exact archived filepath to operate on")

		("include-deleted", "include deleted files")
		("at", po::value<string>(), "restore/list files at the given date (yyyy-mm-dd hh:mm:ss), if omitted will use the newest version")
		;

	po::options_description restoreOptions("Restore options");
	restoreOptions.add_options()
		("dest",   po::value<string>(), "destination directory for restored files")

		/* This does everything except actually write the restored file to disk (decrypts, decompresses and verifies MD5) so it
		 * should be an excellent integrity check:
		 */
		("dry-run", "verify integrity of restored files without actually writing them to disk. Filenames are printed to stdout and "
		"errors to stderr.")
		;


	po::positional_options_description positionalOptions;
	positionalOptions.add("command", -1);

	po::options_description allOptions;
	allOptions.add(mainOptions).add(filterOptions).add(restoreOptions);

	po::variables_map vm;

	try {
		po::store(po::command_line_parser(argc, argv)
			.options(allOptions).positional(positionalOptions).run(), vm);
		po::notify(vm);
	} catch (std::exception &e) {
		cerr << "Error parsing options: " << e.what() << endl;
		return EXIT_FAILURE;
	}

	if (vm.count("help") || !vm.count("command")) {
		cout << "Plan C" << endl;
		cout << allOptions << endl;
		cout << "Commands:" << endl;
		cout << "  recover-key   - Recover your backup encryption key from a CrashPlan ADB directory or cp.properties file" << endl;
		cout << "  derive-key    - Derive an encryption key from an archive password" << endl;
		cout << "  list          - List all filenames that were ever in the backup (incl deleted)" << endl;
		cout << "  list-detailed - List the newest version of files in the backup (add --at for other times)" << endl;
		cout << "  list-all      - List all versions of the files in the backup" << endl;
		cout << "  restore       - Restore files" << endl;
		return EXIT_FAILURE;
	}

	string adbPath;
	string key;

	FilenameMatchMode matchMode = FilenameMatchMode::none;
	string matchString;

	if (vm.count("adb")) {
		adbPath = vm["adb"].as<string>();
	}

	if (vm.count("prefix")) {
		matchString = vm["prefix"].as<string>();
		matchMode = FilenameMatchMode::prefix;
	}

	if (vm.count("filename")) {
		if (matchMode != FilenameMatchMode::none) {
			cerr << "You can't combine the --prefix and --filename flags" << endl;
			return EXIT_FAILURE;
		}

		matchString = vm["filename"].as<string>();
		matchMode = FilenameMatchMode::equals;
	}

	if (vm.count("key")) {
		key = hexStringToBin(vm["key"].as<string>());
	}

    if (vm.count("key64")) {
        key = base64Decode(vm["key64"].as<string>());
    }

	if (adbPath.length() == 0) {
		for (auto &path : {"/Library/Application Support/CrashPlan/conf/adb", "/usr/local/crashplan/conf/adb"}) {
			if (boost::filesystem::is_directory(path)) {
				adbPath = path; // Although we probably can't read this directory without being root
				break;
			}
		}
	}

    if (vm["command"].as<string>() == "derive-key") {
        key = deriveKeyFromPasswordPrompt(vm.count("cpproperties") ? vm["cpproperties"].as<string>() : "");
    }

    if (key.length() == 0 && vm.count("cpproperties")) {
        try {
            key = recoverCPPropertiesKey(vm["cpproperties"].as<string>());
        } catch (std::runtime_error &e) {
            cerr << e.what() << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (key.length() == 0 && adbPath.length() > 0) {
		leveldb::DB *adb;

		try {
			adb = adbOpen(adbPath);
		} catch (std::runtime_error &e) {
			cerr << "Failed to open ADB (" + adbPath + ") to recover your decryption key:" << endl;
			cerr << e.what() << endl << endl;
			cerr << "You may need to run 'sudo ./plan-c recover-key' to have enough permission to read that directory, then pass the recovered key to the --key option." << endl << endl;
			cerr << "Also check that the Crashplan service is not running (it holds a lock on ADB), try one of these:" << endl;
			cerr << "  macOS   - sudo launchctl unload /Library/LaunchDaemons/com.crashplan.engine.plist" << endl;
			cerr << "  Windows - net stop CrashPlanService" << endl;
			cerr << "  Linux   - sudo service crashplan stop" << endl;
			cerr << "  Other   - https://support.code42.com/CrashPlan/4/Troubleshooting/Stop_and_start_the_Code42_app_service" << endl;

			return EXIT_FAILURE;
		}

		if (vm["command"].as<string>() == "recover-keys") {
			cerr << "All unobfuscated values from adb:" << endl;

			std::vector<std::pair<std::string, std::string>> values;

			adbReadAllKeys(adb, values);

			for (auto pair : values) {
				bool printable = true;

				for (int i = 0; i < pair.second.length(); i++) {
					if (!isprint(pair.second[i])) {
						printable = false;
						break;
					}
				}

				if (printable) {
					cout << pair.first << "= " << pair.second << endl;
				} else {
					cout << pair.first << " (hex) = " << binStringToHex(pair.second) << endl;
				}
			}

			cerr << endl;

			return EXIT_SUCCESS;
		}

		key = recoverADBKey(adb);
	}

	if (key.length() == 0 && adbPath.length() == 0) {
		cerr << "Couldn't find your decryption key automatically, you must supply one of the --adb, --cpproperties, --key or --key64 options" << endl;
		return EXIT_FAILURE;
	}

	if (vm["command"].as<string>() == "recover-key" || vm["command"].as<string>() == "recover-keys" || vm["command"].as<string>() == "derive-key") {
		cerr << "Here's your recovered decryption key (for use with --key):" << endl;
		cout << binStringToHex(key) << endl;
		return EXIT_SUCCESS;
	}

	if (vm["command"].as<string>() == "list" || vm["command"].as<string>() == "list-detailed"
			|| vm["command"].as<string>() == "list-all" || vm["command"].as<string>() == "restore") {
		if (!vm.count("archive")) {
			cerr << "You must supply the --archive option" << endl;
			return EXIT_FAILURE;
		}

		bool includeDeleted = vm.count("include-deleted") > 0;
		time_t at = vm.count("at") ? parseDateTime(vm["at"].as<string>()) : 0;

		boost::filesystem::path archivePath(vm["archive"].as<string>());
		BackupArchive *backupArchive;

		try {
			backupArchive = new BackupArchive(archivePath, key);
		} catch (std::runtime_error & e) {
			cerr << "Fatal error opening backup archive: " << e.what() << endl;
			return EXIT_FAILURE;
		}

		if (vm["command"].as<string>() == "list" || vm["command"].as<string>() == "list-detailed"
			|| vm["command"].as<string>() == "list-all") {

			FileListDetailLevel detailLevel;
			TimeMode timeMode;

			if (vm["command"].as<string>() == "list-all") {
				detailLevel = FileListDetailLevel::detailed;
				timeMode = TimeMode::all;
			} else if (vm["command"].as<string>() == "list-detailed") {
				detailLevel = FileListDetailLevel::detailed;

				if (vm.count("at")) {
					timeMode = TimeMode::atTime;
				} else {
					timeMode = TimeMode::latest;
				}
			} else {
				detailLevel = FileListDetailLevel::basic;
				timeMode = TimeMode::latest;
			}

			auto begin = backupArchive->begin(matchMode, matchString);
			auto end = backupArchive->end();

			listBackupFiles(*backupArchive, begin, end, detailLevel, includeDeleted, timeMode, at);

			return EXIT_SUCCESS;
		} else if (vm["command"].as<string>() == "restore") {
			bool dryRun = vm.count("dry-run") > 0;
			boost::filesystem::path destDirectory;

			if (!dryRun) {
				if (!vm.count("dest")) {
					cerr << "You must a --dest to specify where restored files should be saved to" << endl;
					return EXIT_FAILURE;
				}

				destDirectory = boost::filesystem::path(vm["dest"].as<string>());

				if (!boost::filesystem::is_directory(destDirectory)) {
					cerr << "Destination '" + destDirectory.string() + "' is not a directory." << endl;
					return EXIT_FAILURE;
				}
			}

			cerr << "Caching block indexes in memory..." << endl;
			backupArchive->cacheBlockIndex();

			if (dryRun) {
				cerr << "Verifying archive integrity without restoring (dry-run)..." << endl;
			} else {
				cerr << "Restoring files..." << endl;
			}

			auto begin = backupArchive->begin(matchMode, matchString);
			auto end = backupArchive->end();

			TimeMode timeMode = vm.count("at") ? TimeMode::atTime : TimeMode::latest;

			bool success = restoreBackupFiles(*backupArchive, begin, end, destDirectory, includeDeleted, timeMode, at, dryRun);

			if (success) {
				cerr << "Done!" << endl;
				return EXIT_SUCCESS;
			} else {
				cerr << "Errors were encountered during this restore" << endl;
				return EXIT_FAILURE;
			}
		}
	}

	cerr << "Missing command to run" << endl;
}