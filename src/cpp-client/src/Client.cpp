#include "Client.h"
#include "CryptoUtils.h"
#include "Message.h"
#include "Conversation.h"
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include <map>
#include <set>
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

// Escape a string for safe embedding inside a JSON double-quoted value.
// Handles backslash and double-quote (the two characters that break JSON string
// literals when built by concatenation), plus common control characters.
static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                // Other control characters as \uXXXX
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
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
    std::string body = "{\"username\":\"" + jsonEscape(username) +
                       "\",\"password\":\"" + jsonEscape(password) +
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
    std::string body = "{\"username\":\"" + jsonEscape(username) +
                       "\",\"password\":\"" + jsonEscape(password) + "\"}";
    std::string response = http->post(serverUrl + "/auth/login", body);
    token = extractField(response, "token");
    if (token.empty()) {
        std::cerr << "Login failed: " << response << "\n";
        return false;
    }
    // Decode JWT payload to extract integer user id
    auto dot1 = token.find('.');
    auto dot2 = token.find('.', dot1 + 1);
    if (dot1 != std::string::npos && dot2 != std::string::npos) {
        std::string payload = decodeBase64Url(token.substr(dot1 + 1, dot2 - dot1 - 1));
        userId = extractIntField(payload, "id");
    }
    currentUser_ = std::make_unique<User>(username, publicKeyB64);
    std::cout << "Logged in as " << currentUser_->getUsername()
              << " (userId=" << userId << ").\n";
    return true;
}

bool Client::changePassword(const std::string& currentPassword, const std::string& newPassword) {
    std::string body = "{\"currentPassword\":\"" + jsonEscape(currentPassword) +
                       "\",\"newPassword\":\"" + jsonEscape(newPassword) + "\"}";
    std::string response = http->put(serverUrl + "/auth/password", body, token);
    if (response.find("\"message\"") == std::string::npos) {
        std::cerr << "Password change failed: " << response << "\n";
        return false;
    }
    std::cout << "Password updated. Please log in again.\n";
    token.clear();
    currentUser_.reset();
    return true;
}

void Client::sendMessage(int recipientUserId, const std::string& plaintext) {
    std::string pubkeyUrl  = serverUrl + "/users/" + std::to_string(recipientUserId) + "/pubkey";
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

    std::string body = "{\"to\":" + std::to_string(recipientUserId) +
                       ",\"enc\":\"" + CryptoUtils::toBase64(encOut) +
                       "\",\"ciphertext\":\"" + CryptoUtils::toBase64(payload) + "\"}";
    std::string response = http->post(serverUrl + "/messages", body, token);  // enc/ct are base64 — no escaping needed
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
    auto objects = splitJsonArray(response);

    if (objects.empty()) {
        std::cout << "No messages.\n";
        return;
    }

    // Build a list of sender IDs to count sent vs received with std::count
    std::vector<std::string> fromList;
    fromList.reserve(objects.size());
    for (const auto& obj : objects)
        fromList.push_back(std::to_string(extractIntField(obj, "from")));

    int sentCount     = static_cast<int>(
        std::count(fromList.begin(), fromList.end(), std::to_string(userId)));
    int receivedCount = static_cast<int>(objects.size()) - sentCount;

    // Collect unique conversation partners with std::set (sorted, deduplicated)
    std::set<std::string> partners;
    for (size_t i = 0; i < objects.size(); ++i) {
        const std::string& from = fromList[i];
        std::string to = std::to_string(extractIntField(objects[i], "to"));
        partners.insert(from == std::to_string(userId) ? to : from);
    }

    std::cout << objects.size() << " message(s): "
              << receivedCount << " received, "
              << sentCount     << " sent across "
              << partners.size() << " conversation(s).\n\n";

    // Pre-fetch public keys for every unique sender so decryptMessage can verify sender identity.
    // TOFU pin check: if the key has changed since first contact, skip decryption and warn.
    std::map<std::string, std::vector<unsigned char>> senderPubKeys;
    std::set<std::string> untrustedSenders;
    for (size_t i = 0; i < objects.size(); ++i) {
        const std::string& from = fromList[i];
        if (from != std::to_string(userId) && !senderPubKeys.count(from)
                && !untrustedSenders.count(from)) {
            std::string pkResp = http->get(serverUrl + "/users/" + from + "/pubkey", token);
            std::string pkB64  = extractField(pkResp, "publicKey");
            if (pkB64.empty()) {
                untrustedSenders.insert(from);
                continue;
            }
            if (!keyStore_.verifyAndPin(from, pkB64)) {
                std::cout << "WARNING: public key for user " << from
                          << " has changed — possible MITM. Messages from this sender "
                          << "will not be decrypted until you verify the key change.\n";
                untrustedSenders.insert(from);
                continue;
            }
            senderPubKeys[from] = CryptoUtils::fromBase64(pkB64);
        }
    }

    // Group into conversations by partner using std::map (sorted by partner ID)
    std::map<std::string, Conversation> conversations;
    store = std::make_unique<MessageStore>();

    for (const auto& obj : objects) {
        std::string id      = std::to_string(extractIntField(obj, "messageId"));
        std::string from    = std::to_string(extractIntField(obj, "from"));
        std::string to      = std::to_string(extractIntField(obj, "to"));
        std::string enc     = extractField(obj, "enc");
        std::string ct      = extractField(obj, "ciphertext");
        std::string sentAt  = extractField(obj, "sentAt");
        std::string txHash  = extractField(obj, "txHash");
        std::string partner = (from == std::to_string(userId)) ? to : from;

        std::string plaintext;
        if (from != std::to_string(userId) && untrustedSenders.count(from)) {
            plaintext = "[message not decrypted: sender key could not be verified]";
        } else if (from == std::to_string(userId)) {
            plaintext = "[sent — encrypted to recipient]";
        } else {
            try {
                auto encBytes = CryptoUtils::fromBase64(enc);
                auto ctBytes  = CryptoUtils::fromBase64(ct);
                auto pkIt = senderPubKeys.find(from);
                if (pkIt == senderPubKeys.end())
                    plaintext = "[decryption failed: sender public key unavailable]";
                else
                    plaintext = CryptoUtils::decryptMessage(ctBytes, encBytes, myPrivateKey, pkIt->second);
            } catch (const std::exception& e) {
                plaintext = std::string("[decryption failed: ") + e.what() + "]";
            }
        }

        Message msg(id, from, to, enc, ct, plaintext, txHash, sentAt);
        store->addMessage(msg);

        // try_emplace constructs Conversation only if the key is new
        conversations.try_emplace(partner, std::to_string(userId), partner);
        conversations.at(partner).addMessage(msg);
    }

    // Display each conversation — copy messages into a sortable vector, then sort by time
    for (auto& [partner, conv] : conversations) {
        std::cout << "=== Conversation with user " << partner << " ===\n";

        std::vector<Message> display;
        display.reserve(conv.getMessages().size());
        std::copy(conv.getMessages().begin(), conv.getMessages().end(),
                  std::back_inserter(display));
        std::sort(display.begin(), display.end(),
            [](const Message& a, const Message& b) { return a.getSentAt() < b.getSentAt(); });

        for (const auto& m : display) {
            const char* dir = (m.getSender() == std::to_string(userId)) ? "->" : "<-";
            std::cout << dir << " [" << m.getSentAt() << "] (id:" << m.getId() << ") "
                      << m.getPlaintext() << "\n";
        }
        std::cout << "\n";
    }
}

void Client::downloadMessage(const std::string& messageId) {
    std::string response = http->get(serverUrl + "/messages/" + messageId + "/download", token);

    std::string enc    = extractField(response, "enc");
    std::string ct     = extractField(response, "ciphertext");
    std::string txHash = extractField(response, "txHash");
    std::string sentAt = extractField(response, "sentAt");
    std::string from   = std::to_string(extractIntField(response, "from"));

    if (enc.empty() || ct.empty()) {
        std::cerr << "Download failed: " << response << "\n";
        return;
    }

    std::cout << "Message " << messageId << "  from:" << from << "  [" << sentAt << "]\n";
    std::cout << "txHash: " << txHash << "\n";

    if (from == std::to_string(userId)) {
        std::cout << "Content: [sent message — encrypted to recipient, cannot decrypt]\n";
        return;
    }

    std::string pkResp = http->get(serverUrl + "/users/" + from + "/pubkey", token);
    std::string pkB64  = extractField(pkResp, "publicKey");

    try {
        if (pkB64.empty()) throw std::runtime_error("sender public key unavailable");
        auto encBytes = CryptoUtils::fromBase64(enc);
        auto ctBytes  = CryptoUtils::fromBase64(ct);
        auto senderPk = CryptoUtils::fromBase64(pkB64);
        std::string plaintext = CryptoUtils::decryptMessage(ctBytes, encBytes, myPrivateKey, senderPk);
        std::cout << "Content: " << plaintext << "\n";
    } catch (...) {
        std::cout << "Content: [cannot decrypt — key mismatch]\n";
    }
}

void Client::revokeAccess(const std::string& messageId, int targetUserId) {
    std::string url = serverUrl + "/messages/" + messageId +
                      "/share/" + std::to_string(targetUserId);
    std::string response = http->del(url, token);
    std::cout << "Server: " << response << "\n";
}

void Client::deleteMessage(const std::string& messageId) {
    std::string response = http->del(serverUrl + "/messages/" + messageId, token);
    std::cout << "Server: " << response << "\n";
}

bool Client::isLoggedIn() const { return currentUser_ != nullptr; }
int  Client::getUserId()  const { return userId; }

std::vector<Message> Client::getCachedMessages() const {
    return store->getAllMessages();
}
