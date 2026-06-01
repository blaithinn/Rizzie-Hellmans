#pragma once
#include <string>
#include <unordered_map>

class KeyStore {
public:
    explicit KeyStore(const std::string& storePath);

    // Returns true if key is trusted (first time seen or matches pinned key).
    // Returns false if key has changed — potential MITM. Prompts user to confirm.
    bool verifyAndPin(const std::string& userId, const std::string& publicKeyB64);

    // Returns the pinned public key for a user, or empty string if not pinned.
    std::string getPinnedKey(const std::string& userId) const;

private:
    std::string storePath_;
    std::unordered_map<std::string, std::string> pins_; // userId -> base64 pubkey
    void load();
    void save() const;
};
