#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <cstdlib>
#include <sodium.h>
#include "Client.h"
#include "HttpClient.h"
#include "CryptoUtils.h"

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialise libsodium\n";
        return 1;
    }

    // --- Passphrase prompt ---
    std::cout << "Enter passphrase: ";
    std::string passphrase;
    std::getline(std::cin, passphrase);
    if (passphrase.empty()) {
        std::cerr << "Passphrase must not be empty\n";
        return 1;
    }

    // --- Key file path: ~/.rizzie/keys/identity.key ---
    const char* home = std::getenv("HOME");
    if (!home) {
        std::cerr << "HOME environment variable not set\n";
        return 1;
    }
    const std::string keyDir  = std::string(home) + "/.rizzie/keys";
    const std::string keyPath = keyDir + "/identity.key";

    std::filesystem::create_directories(keyDir);

    std::vector<unsigned char> myPublicKey, myPrivateKey;

    // TODO 2.10: obtain token via login instead of hardcoding.
    const std::string token = "PASTE_JWT_HERE";

    if (std::filesystem::exists(keyPath)) {
        // --- Load existing key pair ---
        try {
            myPrivateKey = CryptoUtils::loadPrivateKey(passphrase, keyPath);
        } catch (const std::exception& e) {
            std::cerr << "Failed to load private key: " << e.what() << "\n";
            return 1;
        }
        // Derive public key from private key using X25519 scalar multiplication
        myPublicKey.resize(crypto_box_PUBLICKEYBYTES);
        if (crypto_scalarmult_base(myPublicKey.data(), myPrivateKey.data()) != 0) {
            std::cerr << "Failed to derive public key from private key\n";
            return 1;
        }
        std::cout << "Loaded existing key pair.\n";
    } else {
        // --- Generate new key pair and persist it ---
        try {
            CryptoUtils::generateKeyPair(myPublicKey, myPrivateKey);
            CryptoUtils::savePrivateKey(myPrivateKey, passphrase, keyPath);
        } catch (const std::exception& e) {
            std::cerr << "Failed to generate/save key pair: " << e.what() << "\n";
            return 1;
        }

        // Publish public key to server
        HttpClient http;
        const std::string pubKeyB64 = CryptoUtils::toBase64(myPublicKey);
        const std::string body = "{\"publicKey\":\"" + pubKeyB64 + "\"}";
        std::string putResp = http.put(
            "https://rizzie-hellmans.theburkenator.com/api/v1/users/pubkey",
            body, token);
        std::cout << "Published public key. Server response: " << putResp << "\n";
    }

    std::cout << "Local pubkey (base64): " << CryptoUtils::toBase64(myPublicKey) << "\n\n";

    Client client("https://rizzie-hellmans.theburkenator.com/api/v1");
    client.fetchAndDecryptMessages(myPrivateKey, token);

    return 0;
}
