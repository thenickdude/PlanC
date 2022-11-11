#include <cassert>
#include <cstdio>
#include <vector>

#include "adb.h"
#include "common.h"
#include "crypto.h"
#include "comparator.h"

#include "cryptopp/sha.h"

#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/string_file.hpp"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <dpapi.h>
#endif

#ifdef __APPLE__
#include <CoreFoundation/CFString.h>
#include <IOKit/IOKitLib.h>
#endif

// CrashPlan Home:
static const std::string OBFUSCATION_KEY = "HWANToDk3L6hcXryaU95X6fasmufN8Ok";

static Code42AES256RandomIV aes256;

static std::vector<std::string> platformKeys(1, OBFUSCATION_KEY);

std::pair<std::string, std::string> makeMacPlatformIDFromSerial(const std::string &serial) {
    std::string output = serial + serial + serial + serial + "\n";

    return std::make_pair(output, output.substr(0, 32));
}

#ifdef __APPLE__

static std::pair<std::string, std::string> getMacPlatformID() {
    char buffer[64];

    io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
    CFStringRef uuidCf = (CFStringRef) IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);
    IOObjectRelease(ioRegistryRoot);
    
    if (!CFStringGetCString(uuidCf, buffer, sizeof(buffer), kCFStringEncodingMacRoman)) {
        throw std::runtime_error("Serial number too long for buffer");
    }
    
    CFRelease(uuidCf);
    
    return makeMacPlatformIDFromSerial(std::string(buffer));
}

#endif

std::pair<std::string, std::string> makeLinuxPlatformIDFromSerial(const std::string &serial) {
    return std::make_pair(serial, serial.substr(0, 32));
}

static std::pair<std::string, std::string> getLinuxPlatformID() {
    std::string id1 = "", id2 = "";

    try {
        boost::filesystem::load_string_file(boost::filesystem::path("/var/lib/dbus/machine-id"), id1);
    } catch (...) {
    }

    try {
        boost::filesystem::load_string_file(boost::filesystem::path("/etc/machine-id"), id2);
    } catch (...) {
    }

    std::string serial = id1 + id2;
    
    return makeLinuxPlatformIDFromSerial(serial);
}

/**
 * Attempt decryption using DPAPI and return true if successful
 */
static bool deobfuscateWin32(const std::string &input, std::string &output) {
#ifdef _WIN32
    DATA_BLOB in, out;
    
    in.cbData = input.length();
    in.pbData = (BYTE*) input.data();
    
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
        std::string result((const char *)out.pbData, out.cbData);
         
        LocalFree(out.pbData);
         
        output = result;
        
        return true;
    }
#endif

    return false;
}

void adbInitPlatformKeys(const std::string &macOSSerial, const std::string &linuxSerial) {
    std::pair<std::string, std::string> platformID;

    if (macOSSerial.length() > 0) {
        platformID = makeMacPlatformIDFromSerial(macOSSerial);
    } else if (linuxSerial.length() > 0) {
        platformID = makeLinuxPlatformIDFromSerial(linuxSerial);
    } else {
#ifdef __APPLE__
        platformID = getMacPlatformID();
#else
#ifdef _WIN32
        // Windows uses DPAPI instead
        return;
#else
        // Linux, etc.
        platformID = getLinuxPlatformID();
#endif
#endif
    }
    
    if (platformID.first.length() < 32) {
        return;
    }

    platformKeys.push_back(generateSmallBusinessKeyV2(platformID.first, platformID.second));
}

static std::string adbDeobfuscate(const std::string &value) {
    std::string result;
    
    if (deobfuscateWin32(value, result)) {
        return result;
    }
    
    for (std::string key : platformKeys) {
        try {
            return aes256.decrypt(value, key);
        } catch (BadPaddingException &e) {
        }
    }

    throw std::runtime_error("Failed to deobfuscate values from ADB, bad serial number? "
         "If you're using CrashPlan for Small Business, please see the readme for instructions.");
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
		return adbDeobfuscate(value);
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
		result.push_back(std::pair<std::string,std::string>(it->key().ToString(), adbDeobfuscate(it->value().ToString())));
	}

	bool success = it->status().ok();

	delete it;

	return success;
}