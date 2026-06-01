#include "KeyStore.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>

KeyStore::KeyStore(const std::string& storePath) : storePath_(storePath) {
    load();
}

bool KeyStore::verifyAndPin(const std::string& userId, const std::string& publicKeyB64) {
    auto it = pins_.find(userId);
    if (it == pins_.end()) {
        pins_[userId] = publicKeyB64;
        save();
        return true;
    }
    if (it->second == publicKeyB64) {
        return true;
    }
    std::cout << "WARNING: Public key for user " << userId
              << " has changed. Possible MITM attack. Proceed? (y/n) ";
    std::string answer;
    std::getline(std::cin, answer);
    if (answer == "y" || answer == "Y") {
        pins_[userId] = publicKeyB64;
        save();
        return true;
    }
    return false;
}

std::string KeyStore::getPinnedKey(const std::string& userId) const {
    auto it = std::find_if(pins_.begin(), pins_.end(),
        [&userId](const auto& pair) { return pair.first == userId; });
    if (it == pins_.end()) return "";
    return it->second;
}

void KeyStore::load() {
    std::ifstream file(storePath_);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        pins_[line.substr(0, colon)] = line.substr(colon + 1);
    }
}

void KeyStore::save() const {
    std::filesystem::create_directories(
        std::filesystem::path(storePath_).parent_path());
    std::ofstream file(storePath_);
    for (const auto& [userId, key] : pins_) {
        file << userId << ":" << key << "\n";
    }
}
