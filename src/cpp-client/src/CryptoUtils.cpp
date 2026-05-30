#include "CryptoUtils.h"
#include <sodium.h>
#include <stdexcept>

void CryptoUtils::generateKeyPair(std::vector<unsigned char>& publicKey,
                                   std::vector<unsigned char>& privateKey) {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }

    publicKey.resize(crypto_box_PUBLICKEYBYTES);
    privateKey.resize(crypto_box_SECRETKEYBYTES);

    crypto_box_keypair(publicKey.data(), privateKey.data());
}

std::string CryptoUtils::toBase64(const std::vector<unsigned char>& data) {
    size_t b64len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string result(b64len, '\0');
    sodium_bin2base64(result.data(), b64len, data.data(), data.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    // remove null terminator sodium adds
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

std::vector<unsigned char> CryptoUtils::fromBase64(const std::string& b64) {
    std::vector<unsigned char> bin(b64.size());
    size_t binLen = 0;
    if (sodium_base642bin(bin.data(), bin.size(),
                          b64.data(), b64.size(),
                          nullptr, &binLen, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("Invalid base64 input");
    }
    bin.resize(binLen);
    return bin;
}
