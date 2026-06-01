#include "Client.h"
#include "CryptoUtils.h"
#include <iostream>
#include <stdexcept>

// Extract a string value from a flat JSON object — safe for the base64/token/timestamp
// values the server returns (no embedded quotes or escape sequences in those fields).
static std::string extractField(const std::string& json, const std::string& field) {
    std::string key = "\"" + field + "\"";
    auto pos = json.find(key);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + key.size());
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

// Walk the string tracking brace depth to pull out each {...} object in a JSON array.
static std::vector<std::string> splitJsonArray(const std::string& json) {
    std::vector<std::string> objects;
    int depth = 0;
    size_t start = std::string::npos;
    for (size_t i = 0; i < json.size(); ++i) {
        if (json[i] == '{') {
            if (depth == 0) start = i;
            ++depth;
        } else if (json[i] == '}') {
            --depth;
            if (depth == 0 && start != std::string::npos) {
                objects.push_back(json.substr(start, i - start + 1));
                start = std::string::npos;
            }
        }
    }
    return objects;
}

Client::Client(const std::string& url) : serverUrl(url) {
    http = std::make_unique<HttpClient>();
}

void Client::fetchAndDecryptMessages(const std::vector<unsigned char>& myPrivateKey,
                                     const std::string& token) {
    std::string response = http->get(serverUrl + "/messages", token);

    for (const auto& obj : splitJsonArray(response)) {
        std::string from       = extractField(obj, "from");
        std::string enc        = extractField(obj, "enc");        // ephemeral pubkey
        std::string ciphertext = extractField(obj, "ciphertext"); // nonce || ciphertext+tag
        std::string sentAt     = extractField(obj, "sentAt");

        try {
            auto encBytes        = CryptoUtils::fromBase64(enc);
            auto ciphertextBytes = CryptoUtils::fromBase64(ciphertext);
            std::string plaintext = CryptoUtils::decryptMessage(ciphertextBytes, encBytes, myPrivateKey);
            std::cout << "From: " << from << "  [" << sentAt << "]\n"
                      << "  " << plaintext << "\n\n";
        } catch (const std::exception& e) {
            std::cerr << "Could not decrypt message from " << from << ": " << e.what() << "\n";
        }
    }
}
