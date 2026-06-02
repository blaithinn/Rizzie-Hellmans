#include "User.h"

User::User(const std::string& username, const std::string& publicKey)
    : username(username), publicKey(publicKey) {}

const std::string& User::getUsername() const { return username; }
const std::string& User::getPublicKey() const { return publicKey; }
