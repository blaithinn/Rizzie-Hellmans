#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <cstdlib>
#include <sodium.h>
#include "Client.h"
#include "CryptoUtils.h"

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialise libsodium\n";
        return 1;
    }

    std::cout << "Enter passphrase: ";
    std::string passphrase;
    std::getline(std::cin, passphrase);
    if (passphrase.empty()) {
        std::cerr << "Passphrase must not be empty\n";
        return 1;
    }

    const char* home = std::getenv("HOME");
    if (!home) {
        std::cerr << "HOME environment variable not set\n";
        return 1;
    }
    const std::string keyDir  = std::string(home) + "/.rizzie/keys";
    const std::string keyPath = keyDir + "/identity.key";
    std::filesystem::create_directories(keyDir);

    std::vector<unsigned char> myPublicKey, myPrivateKey;

    if (std::filesystem::exists(keyPath)) {
        try {
            myPrivateKey = CryptoUtils::loadPrivateKey(passphrase, keyPath);
        } catch (const std::exception& e) {
            std::cerr << "Failed to load private key: " << e.what() << "\n";
            return 1;
        }
        myPublicKey.resize(crypto_box_PUBLICKEYBYTES);
        if (crypto_scalarmult_base(myPublicKey.data(), myPrivateKey.data()) != 0) {
            std::cerr << "Failed to derive public key from private key\n";
            return 1;
        }
        std::cout << "Loaded existing key pair.\n";
    } else {
        try {
            CryptoUtils::generateKeyPair(myPublicKey, myPrivateKey);
            CryptoUtils::savePrivateKey(myPrivateKey, passphrase, keyPath);
        } catch (const std::exception& e) {
            std::cerr << "Failed to generate/save key pair: " << e.what() << "\n";
            return 1;
        }
        std::cout << "Generated new key pair.\n";
    }

    std::cout << "Local pubkey (base64): " << CryptoUtils::toBase64(myPublicKey) << "\n\n";

    Client client("https://rizzie-hellmans.theburkenator.com");
    client.setKeyPair(myPublicKey, myPrivateKey);

    while (true) {
        std::cout << "\n1. Register\n"
                     "2. Login\n"
                     "3. Send message\n"
                     "4. View inbox\n"
                     "5. Forward message\n"
                     "6. Change password\n"
                     "7. Download message\n"
                     "8. Revoke access\n"
                     "9. Delete message\n"
                     "0. Quit\n"
                     "Choice: ";

        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        int choice = -1;
        try { choice = std::stoi(line); } catch (...) {}

        switch (choice) {
        case 1: {
            std::string username, password;
            std::cout << "Username: ";
            std::getline(std::cin, username);
            std::cout << "Password: ";
            std::getline(std::cin, password);
            client.registerUser(username, password);
            break;
        }
        case 2: {
            std::string username, password;
            std::cout << "Username: ";
            std::getline(std::cin, username);
            std::cout << "Password: ";
            std::getline(std::cin, password);
            client.login(username, password);
            break;
        }
        case 3: {
            if (!client.isLoggedIn()) { std::cout << "Please login first.\n"; break; }
            std::string recipStr, plaintext;
            std::cout << "Recipient user ID: ";
            std::getline(std::cin, recipStr);
            std::cout << "Message: ";
            std::getline(std::cin, plaintext);
            try {
                client.sendMessage(std::stoi(recipStr), plaintext);
            } catch (...) {
                std::cerr << "Invalid recipient ID.\n";
            }
            break;
        }
        case 4: {
            if (!client.isLoggedIn()) { std::cout << "Please login first.\n"; break; }
            client.fetchAndDecryptMessages();
            break;
        }
        case 5: {
            if (!client.isLoggedIn()) { std::cout << "Please login first.\n"; break; }
            std::string msgId, recipStr;
            std::cout << "Message ID to forward: ";
            std::getline(std::cin, msgId);
            std::cout << "Recipient user ID: ";
            std::getline(std::cin, recipStr);
            try {
                client.forwardMessage(msgId, std::stoi(recipStr));
            } catch (...) {
                std::cerr << "Invalid recipient ID.\n";
            }
            break;
        }
        case 6: {
            if (!client.isLoggedIn()) { std::cout << "Please login first.\n"; break; }
            std::string current, next;
            std::cout << "Current password: ";
            std::getline(std::cin, current);
            std::cout << "New password: ";
            std::getline(std::cin, next);
            client.changePassword(current, next);
            break;
        }
        case 7: {
            if (!client.isLoggedIn()) { std::cout << "Please login first.\n"; break; }
            std::string msgId;
            std::cout << "Message ID to download: ";
            std::getline(std::cin, msgId);
            client.downloadMessage(msgId);
            break;
        }
        case 8: {
            if (!client.isLoggedIn()) { std::cout << "Please login first.\n"; break; }
            std::string msgId, uidStr;
            std::cout << "Message ID: ";
            std::getline(std::cin, msgId);
            std::cout << "User ID to revoke: ";
            std::getline(std::cin, uidStr);
            try {
                client.revokeAccess(msgId, std::stoi(uidStr));
            } catch (...) {
                std::cerr << "Invalid user ID.\n";
            }
            break;
        }
        case 9: {
            if (!client.isLoggedIn()) { std::cout << "Please login first.\n"; break; }
            std::string msgId;
            std::cout << "Message ID to delete: ";
            std::getline(std::cin, msgId);
            client.deleteMessage(msgId);
            break;
        }
        case 0:
            std::cout << "Goodbye.\n";
            return 0;
        default:
            std::cout << "Invalid choice, enter 0-9.\n";
            break;
        }
    }

    return 0;
}
