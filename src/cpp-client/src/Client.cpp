#include "Client.h"
#include "CryptoUtils.h"
#include "Message.h"
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include <stdexcept>

static std::string defaultKeyStorePath() {
    const char* home = std::getenv("HOME");
    return std::string(home ? home : ".") + "/.rizzie/keys/trusted_keys.txt";
}

// Extract a string value from a flat JSON object — safe for base64/token/timestamp
// fields that contain no embedded quotes or escape sequences.
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

// Extract an integer value from a flat JSON object.
static int extractIntField(const std::string& json, const std::string& field) {
    std::string key = "\"" + field + "\"";
    auto pos = json.find(key);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos + key.size());
    if (pos == std::string::npos) return 0;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    size_t end = pos;
    while (end < json.size() && std::isdigit(static_cast<unsigned char>(json[end]))) ++end;
    if (end == pos) return 0;
    return std::stoi(json.substr(pos, end - pos));
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

// Convert base64url to base64 and decode to a UTF-8 string (for JWT payload).
static std::string decodeBase64Url(const std::string& input) {
    std::string b64 = input;
    for (auto& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b64.size() % 4 != 0) b64 += '=';
    auto bytes = CryptoUtils::fromBase64(b64);
    return std::string(bytes.begin(), bytes.end());
}

Client::Client(const std::string& url) : serverUrl(url), keyStore_(defaultKeyStorePath()) {
    http  = std::make_unique<HttpClient>();
    store = std::make_unique<MessageStore>();
}

void Client::setKeyPair(const std::vector<unsigned char>& publicKey,
                        const std::vector<unsigned char>& privateKey) {
    myPublicKey  = publicKey;
    myPrivateKey = privateKey;
    publicKeyB64 = CryptoUtils::toBase64(publicKey);
}

bool Client::registerUser(const std::string& username, const std::string& password) {
    std::string url  = serverUrl + "/auth/register";
    std::string body = "{\"username\":\"" + username +
                       "\",\"password\":\"" + password +
                       "\",\"publicKey\":\"" + publicKeyB64 + "\"}";

    std::string response = http->post(url, body);

    if (response.find("\"message\"") == std::string::npos) {
        std::cerr << "Registration failed: " << response << "\n";
        return false;
    }
    std::cout << "Registered successfully.\n";
    return true;
}

bool Client::login(const std::string& username, const std::string& password) {
    std::string body = "{\"username\":\"" + username +
                       "\",\"password\":\"" + password + "\"}";
    std::string response = http->post(serverUrl + "/auth/login", body);
    token = extractField(response, "token");
    if (token.empty()) {
        std::cerr << "Login failed: " << response << "\n";
        return false;
    }
    // Decode JWT payload (base64url middle section) to extract integer user id
    auto dot1 = token.find('.');
    auto dot2 = token.find('.', dot1 + 1);
    if (dot1 != std::string::npos && dot2 != std::string::npos) {
        std::string payload = decodeBase64Url(token.substr(dot1 + 1, dot2 - dot1 - 1));
        userId = extractIntField(payload, "id");
    }
    std::cout << "Logged in as " << username << " (userId=" << userId << ").\n";
    return true;
}

void Client::sendMessage(int recipientUserId, const std::string& plaintext) {
    std::string pubkeyUrl = serverUrl + "/users/" + std::to_string(recipientUserId) + "/pubkey";
    std::string pubkeyResp = http->get(pubkeyUrl, token);
    std::string recipPubKeyB64 = extractField(pubkeyResp, "publicKey");
    if (recipPubKeyB64.empty()) {
        std::cerr << "Could not fetch recipient public key: " << pubkeyResp << "\n";
        return;
    }

    if (!keyStore_.verifyAndPin(std::to_string(recipientUserId), recipPubKeyB64)) {
        std::cerr << "Aborted: key verification failed for user " << recipientUserId << "\n";
        return;
    }

    auto recipPubKey = CryptoUtils::fromBase64(recipPubKeyB64);

    std::vector<unsigned char> encOut;
    auto payload = CryptoUtils::encryptMessage(plaintext, recipPubKey, myPrivateKey, encOut);

    std::string encB64        = CryptoUtils::toBase64(encOut);
    std::string ciphertextB64 = CryptoUtils::toBase64(payload);

    std::string url  = serverUrl + "/messages";
    std::string body = "{\"to\":" + std::to_string(recipientUserId) +
                       ",\"enc\":\"" + encB64 +
                       "\",\"ciphertext\":\"" + ciphertextB64 + "\"}";
    std::string response = http->post(url, body, token);
    std::cout << "Message sent. Server: " << response << "\n";
}

void Client::forwardMessage(const std::string& messageId, int recipientUserId) {
    const Message* msg = store->findById(messageId);
    if (!msg) {
        std::cerr << "Message " << messageId << " not found locally — view inbox first.\n";
        return;
    }

    std::string pubkeyResp = http->get(
        serverUrl + "/users/" + std::to_string(recipientUserId) + "/pubkey", token);
    std::string recipPubKeyB64 = extractField(pubkeyResp, "publicKey");
    if (recipPubKeyB64.empty()) {
        std::cerr << "Could not fetch recipient public key: " << pubkeyResp << "\n";
        return;
    }

    if (!keyStore_.verifyAndPin(std::to_string(recipientUserId), recipPubKeyB64)) {
        std::cerr << "Aborted: key verification failed for user " << recipientUserId << "\n";
        return;
    }

    auto recipPubKey = CryptoUtils::fromBase64(recipPubKeyB64);
    std::vector<unsigned char> encOut;
    auto payload = CryptoUtils::encryptMessage(msg->getPlaintext(), recipPubKey, myPrivateKey, encOut);

    std::string body = "{\"to\":" + std::to_string(recipientUserId) +
                       ",\"enc\":\"" + CryptoUtils::toBase64(encOut) +
                       "\",\"ciphertext\":\"" + CryptoUtils::toBase64(payload) + "\"}";
    std::string fwdResponse = http->post(
        serverUrl + "/messages/" + messageId + "/forward", body, token);
    std::cout << "Message forwarded. Server: " << fwdResponse << "\n";
}

void Client::fetchAndDecryptMessages() {
    std::string response = http->get(serverUrl + "/messages", token);

    std::vector<Message> msgs;
    for (const auto& obj : splitJsonArray(response)) {
        std::string id         = std::to_string(extractIntField(obj, "messageId"));
        std::string from       = std::to_string(extractIntField(obj, "from"));
        std::string enc        = extractField(obj, "enc");
        std::string ciphertext = extractField(obj, "ciphertext");
        std::string sentAt     = extractField(obj, "sentAt");

        try {
            auto encBytes         = CryptoUtils::fromBase64(enc);
            auto ciphertextBytes  = CryptoUtils::fromBase64(ciphertext);
            std::string plaintext = CryptoUtils::decryptMessage(ciphertextBytes, encBytes, myPrivateKey);
            msgs.emplace_back(id, from, "", enc, ciphertext, plaintext, "", sentAt);
        } catch (const std::exception& e) {
            std::cerr << "Could not decrypt message from " << from << ": " << e.what() << "\n";
        }
    }

    std::sort(msgs.begin(), msgs.end(),
        [](const Message& a, const Message& b) { return a.getSentAt() < b.getSentAt(); });

    store = std::make_unique<MessageStore>();
    for (const auto& m : msgs)
        store->addMessage(m);

    if (msgs.empty()) {
        std::cout << "No messages.\n";
        return;
    }
    for (const auto& m : store->getAllMessages()) {
        std::cout << "ID: " << m.getId() << "  From: " << m.getSender()
                  << "  [" << m.getSentAt() << "]\n"
                  << "  " << m.getPlaintext() << "\n\n";
    }
}

void Client::deleteMessage(const std::string& messageId) {
    // DELETE /messages/:id not yet implemented on server
    std::cout << "Delete not yet implemented on server (id=" << messageId << ").\n";
}

bool Client::isLoggedIn() const { return !token.empty(); }
int  Client::getUserId()  const { return userId; }
