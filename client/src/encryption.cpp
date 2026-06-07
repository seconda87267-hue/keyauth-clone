#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>

namespace crypto {

static std::vector<unsigned char> derive_key(const std::string& base_key) {
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hash_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, base_key.data(), base_key.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(ctx);
    hash.resize(hash_len);
    return hash;
}

std::string base64_encode(const unsigned char* data, size_t len) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(bio, mem);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, (int)len);
    BIO_flush(bio);

    BUF_MEM* buf = nullptr;
    BIO_get_mem_ptr(bio, &buf);
    std::string result(buf->data, buf->length);
    BIO_free_all(bio);
    return result;
}

std::string base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), (int)encoded.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<char> buf(encoded.size());
    int len = BIO_read(bio, buf.data(), (int)buf.size());
    BIO_free_all(bio);
    return std::string(buf.data(), len);
}

std::string hex_encode(const unsigned char* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}

std::string encrypt(const std::string& plaintext, const std::string& key) {
    auto aes_key = derive_key(key);

    // Generate random IV
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), 16);

    // Pad plaintext to block size
    int block_size = 16;
    int padded_len = ((int)plaintext.size() / block_size) * block_size + block_size;
    std::vector<unsigned char> padded(padded_len, padded_len - plaintext.size());
    std::memcpy(padded.data(), plaintext.data(), plaintext.size());

    std::vector<unsigned char> ciphertext(padded_len + 64);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv.data());
    int out_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, padded.data(), padded_len);
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    // Prepend IV to ciphertext
    std::vector<unsigned char> combined(iv.begin(), iv.end());
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.begin() + out_len + final_len);

    return base64_encode(combined.data(), combined.size());
}

std::string decrypt(const std::string& ciphertext_b64, const std::string& key) {
    auto aes_key = derive_key(key);
    auto raw = base64_decode(ciphertext_b64);

    if (raw.size() < 16) return "";

    std::vector<unsigned char> iv(raw.begin(), raw.begin() + 16);
    std::vector<unsigned char> ciphertext(raw.begin() + 16, raw.end());

    std::vector<unsigned char> plaintext(ciphertext.size() + 64);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv.data());
    int out_len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(), (int)ciphertext.size());
    int final_len = 0;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    int total = out_len + final_len;
    // Remove PKCS7 padding
    if (total > 0) {
        unsigned char pad = plaintext[total - 1];
        if (pad > 0 && pad <= 16)
            total -= pad;
    }

    return std::string((const char*)plaintext.data(), total);
}

std::string sign(const std::string& data, const std::string& secret) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), secret.data(), (int)secret.size(),
         (const unsigned char*)data.data(), data.size(), md, &md_len);
    return hex_encode(md, md_len);
}

bool verify(const std::string& data, const std::string& signature, const std::string& secret) {
    return sign(data, secret) == signature;
}

} // namespace crypto
