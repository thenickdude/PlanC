#include <cassert>

#include "crypto.h"
#include "common.h"

#include "cryptopp/blowfish.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/sha.h"

static const CryptoPP::byte BLOWFISH_IV[CryptoPP::Blowfish::BLOCKSIZE] = {12, 34, 56, 78, 90, 87, 65, 43};
static const CryptoPP::byte AES_IV[CryptoPP::AES::BLOCKSIZE] = {121, 92, 86, 51, 153, 89, 163, 254, 47, 51, 47, 174, 253, 149, 129, 140};

const Code42Cipher* code42Ciphers[] = {
	new Code42NullCipher(),
	new Code42Blowfish128(),
	new Code42Blowfish448(),
	new Code42AES128(),
	new Code42AES256(),
	new Code42AES256RandomIV()
};

std::string hashPassphraseC42(const std::string &passphrase, const std::string &salt, int iterations) {
    CryptoPP::SHA1 hasher;
    CryptoPP::byte currentHash[CryptoPP::SHA1::DIGESTSIZE];

    hasher.Update((const CryptoPP::byte*) salt.data(), salt.length());
    hasher.Update((const CryptoPP::byte*) passphrase.data(), passphrase.length());

    hasher.Final(currentHash);

    for (int i = 0; i < iterations; i++) {
        hasher.Update(currentHash, sizeof(currentHash));
        hasher.Final(currentHash);
    }

    return base64Encode((char*)currentHash, sizeof(currentHash)) + ":" + base64Encode(salt);
}

/**
 * Test vector: userID=1234, passphrase=hello, output=783630546C5438426B3D3A4D54497A4E413D3D5246355A45456D4679447A672F546477576643366C6A6D663056513D3A4D54497A4E413D3D
 * @param userID 
 * @param passphrase 
 * @return 
 */
std::string deriveCustomArchiveKeyV2(const std::string &userID, const std::string &passphrase) {
	const int OUTPUT_LENGTH = 56;
	const int HASH_ITERATIONS = 50000;

    std::string passphraseReverse(passphrase.rbegin(), passphrase.rend());

    std::string result = hashPassphraseC42(passphrase, userID, HASH_ITERATIONS) + hashPassphraseC42(passphraseReverse, userID, HASH_ITERATIONS);
	
	// Extend the hash with null bytes if needed
	if (result.length() < OUTPUT_LENGTH) {
		result += std::string(OUTPUT_LENGTH - result.length(), (char) 0x00);
	}

	// Keep the trailing bytes
	if (result.length() > OUTPUT_LENGTH) {
		result = result.substr(result.length() - OUTPUT_LENGTH);
	}

	return result;
}

/**
 * Decrypt a value using AES-256 CBC, where the first block is the message IV, and verify the message padding is correct.
 */
std::string Code42AES256RandomIV::decrypt(const std::string & cipherText, const std::string &key) const {
	// We expect the encrypted value to be padded to a full block size (padding)
	if (cipherText.length() % CryptoPP::AES::BLOCKSIZE != 0) {
		throw BadPaddingException();
	}

	// The first block of the input is the random IV:
	const CryptoPP::byte *iv = (const CryptoPP::byte *) cipherText.data();
	const CryptoPP::byte *encrypted = (const CryptoPP::byte *) cipherText.data() + CryptoPP::AES::BLOCKSIZE;
	int encryptedSize = cipherText.length() - CryptoPP::AES::BLOCKSIZE;

	uint8_t *buffer = new uint8_t[encryptedSize];

	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor((const CryptoPP::byte *)key.data(), 256 / 8, iv);

	decryptor.ProcessData(buffer, encrypted, encryptedSize);

	// Verify padding is correct after decryption:
	uint8_t padByte = buffer[encryptedSize - 1];

	if (padByte <= 0 || padByte > CryptoPP::AES::BLOCKSIZE) {
		throw BadPaddingException();
	}

	for (int i = 1; i < padByte; i++) {
		if (buffer[encryptedSize - 1 - i] != padByte) {
			throw BadPaddingException();
		}
	}

	int unpaddedLength = encryptedSize - padByte;

	std::string result((const char *) buffer, unpaddedLength);

	delete[] buffer;

	return result;
}

std::string Code42AESStaticIV::decrypt(const std::string & cipherText, const std::string &key) const {
	// We expect the encrypted value to be padded to a full block size (padding)
	if (cipherText.length() % CryptoPP::AES::BLOCKSIZE != 0) {
		throw BadPaddingException();
	}

	const CryptoPP::byte *encrypted = (const CryptoPP::byte *) cipherText.data();
	int encryptedSize = cipherText.length();

	uint8_t *buffer = new uint8_t[encryptedSize];

	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor((const CryptoPP::byte *)key.data(), 256 / 8, AES_IV);

	decryptor.ProcessData(buffer, encrypted, encryptedSize);

	// Verify padding is correct after decryption:
	uint8_t padByte = buffer[encryptedSize - 1];

	if (padByte <= 0 || padByte > CryptoPP::AES::BLOCKSIZE) {
		throw BadPaddingException();
	}

	for (int i = 1; i < padByte; i++) {
		if (buffer[encryptedSize - 1 - i] != padByte) {
			throw BadPaddingException();
		}
	}

	int unpaddedLength = encryptedSize - padByte;

	std::string result((const char *) buffer, unpaddedLength);

	delete[] buffer;

	return result;
}

std::string Code42Blowfish448::decrypt(const std::string & cipherText, const std::string & key) const {
	// We expect the encrypted value to be padded to a full block size (padding)
	if (cipherText.length() % CryptoPP::Blowfish::BLOCKSIZE != 0) {
		throw BadPaddingException();
	}

	int encryptedSize = cipherText.length();
	CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Decryption decryptor;
	CryptoPP::byte *buffer = new CryptoPP::byte[encryptedSize];

	// Trim overlong key
	std::string newKey(key);

	if (newKey.length() > CryptoPP::Blowfish::MAX_KEYLENGTH) {
		newKey.resize(CryptoPP::Blowfish::MAX_KEYLENGTH);
	}

	decryptor.SetKeyWithIV((const CryptoPP::byte *)newKey.data(), newKey.length(), BLOWFISH_IV);
	decryptor.ProcessData(buffer, (const CryptoPP::byte *) cipherText.data(), cipherText.length());

	// Verify padding is correct after decryption:
	uint8_t padByte = buffer[encryptedSize - 1];

	if (padByte <= 0 || padByte > CryptoPP::Blowfish::BLOCKSIZE) {
		throw BadPaddingException();
	}

	for (int i = 1; i < padByte; i++) {
		if (buffer[encryptedSize - 1 - i] != padByte) {
			throw BadPaddingException();
		}
	}

	int unpaddedLength = encryptedSize - padByte;

	std::string result((const char *) buffer, unpaddedLength);

	delete[] buffer;

	return result;
}
