#include "aead.h"

namespace spark {

// Perform authenticated encryption with ChaCha20-Poly1305 using key commitment
// NOTE: This uses a fixed zero nonce, which is safe when used in Spark as directed
// It is NOT safe in general to do this!
AEADEncryptedData AEAD::encrypt(const GroupElement& prekey, const std::string additional_data, CDataStream& data) {
	// Set up the result structure
	AEADEncryptedData result;

	// Derive the key and commitment
	std::vector<unsigned char> key = SparkUtils::kdf_aead(prekey);
	result.key_commitment = SparkUtils::commit_aead(prekey);

	// Internal size tracker; we know the size of the data already, and can ignore
	int TEMP;

	// For our application, we can safely use a zero nonce since keys are never reused
	std::vector<unsigned char> iv;
	iv.resize(AEAD_IV_SIZE);

	// Set up the cipher
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key.data(), iv.data());

	// Include the associated data
	std::vector<unsigned char> additional_data_bytes(additional_data.begin(), additional_data.end());
	EVP_EncryptUpdate(ctx, NULL, &TEMP, additional_data_bytes.data(), additional_data_bytes.size());

	// Encrypt the plaintext
	result.ciphertext.resize(data.size());
	EVP_EncryptUpdate(ctx, result.ciphertext.data(), &TEMP, reinterpret_cast<unsigned char *>(data.data()), data.size());
	EVP_EncryptFinal_ex(ctx, NULL, &TEMP);

	// Get the tag
	result.tag.resize(AEAD_TAG_SIZE);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_SIZE, result.tag.data());

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	return result;
}

// Perform authenticated decryption with ChaCha20-Poly1305 using key commitment
// NOTE: This uses a fixed zero nonce, which is safe when used in Spark as directed
// It is NOT safe in general to do this!
CDataStream AEAD::decrypt_and_verify(const GroupElement& prekey, const std::string additional_data, AEADEncryptedData& data) {
	// Assert that the key commitment is valid
	std::vector<unsigned char> key_commitment = SparkUtils::commit_aead(prekey);
	if (key_commitment != data.key_commitment) {
		throw std::runtime_error("Bad AEAD key commitment");
	}

	// Derive the key
	std::vector<unsigned char> key = SparkUtils::kdf_aead(prekey);

	// Set up the result
	CDataStream result(SER_NETWORK, PROTOCOL_VERSION);

	// Internal size tracker; we know the size of the data already, and can ignore
	int TEMP;

	// For our application, we can safely use a zero nonce since keys are never reused
	std::vector<unsigned char> iv;
	iv.resize(AEAD_IV_SIZE);

	// Set up the cipher
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key.data(), iv.data());

	// Include the associated data
	std::vector<unsigned char> additional_data_bytes(additional_data.begin(), additional_data.end());
	EVP_DecryptUpdate(ctx, NULL, &TEMP, additional_data_bytes.data(), additional_data_bytes.size());

	// Decrypt the ciphertext
	result.resize(data.ciphertext.size());
	EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(result.data()), &TEMP, data.ciphertext.data(), data.ciphertext.size());
	
	// Set the expected tag
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_SIZE, data.tag.data());

	// Decrypt and clean up
	int ret = EVP_DecryptFinal_ex(ctx, NULL, &TEMP);
	EVP_CIPHER_CTX_free(ctx);
	if (ret != 1) {
		throw std::runtime_error("Bad AEAD authentication");
	}

	return result;
}

// Perform unauthenticated encryption with ChaCha20
// NOTE: This uses a fixed zero nonce, which is safe when used in Spark as directed
// It is NOT safe in general to do this!
std::vector<unsigned char> AEAD::stream_encrypt(const std::vector<unsigned char>& key, CDataStream& data) {
	// Check key size
	if (key.size() != STREAM_KEY_SIZE) {
		throw std::runtime_error("Bad stream cipher key size");
	}

	// Internal size tracker; we know the size of the data already, and can ignore
	int TEMP;

	// For our application, we can safely use a zero nonce since keys are never reused
	std::vector<unsigned char> iv;
	iv.resize(AEAD_IV_SIZE);

	// Set up the cipher
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key.data(), iv.data());

	// Encrypt the plaintext
	std::vector<unsigned char> ciphertext;
	ciphertext.resize(data.size());
	EVP_EncryptUpdate(ctx, ciphertext.data(), &TEMP, reinterpret_cast<unsigned char *>(data.data()), data.size());
	EVP_EncryptFinal_ex(ctx, NULL, &TEMP);

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext;
}

// Perform unauthenticated decryption with ChaCha20
// NOTE: This uses a fixed zero nonce, which is safe when used in Spark as directed
// It is NOT safe in general to do this!
CDataStream AEAD::stream_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
	// Check key size
	if (key.size() != STREAM_KEY_SIZE) {
		throw std::runtime_error("Bad stream cipher key size");
	}

	// Set up the result
	CDataStream result(SER_NETWORK, PROTOCOL_VERSION);

	// Internal size tracker; we know the size of the data already, and can ignore
	int TEMP;

	// For our application, we can safely use a zero nonce since keys are never reused
	std::vector<unsigned char> iv;
	iv.resize(AEAD_IV_SIZE);

	// Set up the cipher
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key.data(), iv.data());

	// Decrypt the ciphertext
	result.resize(data.size());
	EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(result.data()), &TEMP, data.data(), data.size());
	
	// Decrypt and clean up
	EVP_DecryptFinal_ex(ctx, NULL, &TEMP);
	EVP_CIPHER_CTX_free(ctx);

	return result;
}

}
