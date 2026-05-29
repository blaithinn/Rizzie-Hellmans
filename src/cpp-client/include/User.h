#pragma once
#include <string>

class User {
public:
    User(const std::string& username, const std::string& publicKey);
    const std::string& getUsername() const;
    const std::string& getPublicKey() const;
private:
    std::string username;
    std::string publicKey;
};
