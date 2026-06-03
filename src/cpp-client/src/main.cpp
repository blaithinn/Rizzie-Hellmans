#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <cstdlib>
#include <sodium.h>
#include "Client.h"
#include "CryptoUtils.h"

// ANSI colour codes — all terminals on Linux support these
static const char* RESET  = "\033[0m";
static const char* BOLD   = "\033[1m";
static const char* DIM    = "\033[2m";
static const char* CYAN   = "\033[96m";
static const char* GREEN  = "\033[92m";
static const char* YELLOW = "\033[93m";
static const char* GRAY   = "\033[90m";

static void clearScreen() {
    std::cout << "\033[2J\033[H" << std::flush;
}

static void pause() {
    std::cout << "\n" << DIM << "  Press Enter to return to menu..." << RESET << std::flush;
    std::string dummy;
    std::getline(std::cin, dummy);
}

static void drawMenu(bool loggedIn, int userId) {
    clearScreen();

    std::cout << "\n  " << BOLD << CYAN << "Rizzie-Hellmans" << RESET << "  —  Secure E2E Messaging\n";
    std::cout << "  " << std::string(44, '-') << "\n";

    if (loggedIn) {
        std::cout << "  " << GREEN << "● Logged in  " << RESET
                  << GREEN << "(user id: " << BOLD << userId << RESET << GREEN << ")" << RESET << "\n";
    } else {
        std::cout << "  " << YELLOW << "○  Not logged in" << RESET << "\n";
    }

    std::cout << "  " << std::string(44, '-') << "\n\n";

    // Helper: print one menu item, grayed out if login is required and user isn't logged in
    auto item = [&](const char* num, const char* label, bool needsLogin) {
        if (needsLogin && !loggedIn)
            std::cout << "  " << GRAY << num << "  " << label << RESET << "\n";
        else
            std::cout << "  " << BOLD << CYAN << num << RESET << "  " << label << "\n";
    };

    item("1", "Register",         false);
    item("2", "Login",            false);
    item("3", "Send message",     true);
    item("4", "View inbox",       true);
    item("5", "Forward message",  true);
    item("6", "Change password",  true);
    item("7", "Download message", true);
    item("8", "Revoke access",    true);
    item("9", "Delete message",   true);
    std::cout << "  " << DIM << "0  Quit" << RESET << "\n";

    std::cout << "\n  " << std::string(44, '-') << "\n";
    std::cout << "\n  Choice: ";
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialise libsodium\n";
        return 1;
    }

    clearScreen();
    std::cout << "\n  " << BOLD << CYAN << "Rizzie-Hellmans" << RESET << "  —  Key Setup\n\n";
    std::cout << "  Enter passphrase: ";
    std::string passphrase;
    std::getline(std::cin, passphrase);
    if (passphrase.empty()) {
        std::cerr << "  Passphrase must not be empty\n";
        return 1;
    }

    const char* home = std::getenv("HOME");
    if (!home) {
        std::cerr << "  HOME environment variable not set\n";
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
            std::cerr << "  Failed to load private key: " << e.what() << "\n";
            return 1;
        }
        myPublicKey.resize(crypto_box_PUBLICKEYBYTES);
        if (crypto_scalarmult_base(myPublicKey.data(), myPrivateKey.data()) != 0) {
            std::cerr << "  Failed to derive public key from private key\n";
            return 1;
        }
        std::cout << "  " << GREEN << "✓" << RESET << " Loaded existing key pair.\n";
    } else {
        try {
            CryptoUtils::generateKeyPair(myPublicKey, myPrivateKey);
            CryptoUtils::savePrivateKey(myPrivateKey, passphrase, keyPath);
        } catch (const std::exception& e) {
            std::cerr << "  Failed to generate/save key pair: " << e.what() << "\n";
            return 1;
        }
        std::cout << "  " << GREEN << "✓" << RESET << " Generated new key pair.\n";
    }

    std::cout << "\n  " << DIM << "Public key: " << CryptoUtils::toBase64(myPublicKey) << RESET << "\n";
    pause();

    Client client("https://rizzie-hellmans.theburkenator.com");
    client.setKeyPair(myPublicKey, myPrivateKey);

    while (true) {
        drawMenu(client.isLoggedIn(), client.getUserId());

        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        int choice = -1;
        try { choice = std::stoi(line); } catch (...) {}

        switch (choice) {
        case 1: {
            std::string username, password;
            std::cout << "\n  Username: ";
            std::getline(std::cin, username);
            std::cout << "  Password: ";
            std::getline(std::cin, password);
            std::cout << "\n";
            client.registerUser(username, password);
            pause();
            break;
        }
        case 2: {
            std::string username, password;
            std::cout << "\n  Username: ";
            std::getline(std::cin, username);
            std::cout << "  Password: ";
            std::getline(std::cin, password);
            std::cout << "\n";
            client.login(username, password);
            pause();
            break;
        }
        case 3: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; pause(); break; }
            std::string recipStr, plaintext;
            std::cout << "\n  Recipient user ID: ";
            std::getline(std::cin, recipStr);
            std::cout << "  Message: ";
            std::getline(std::cin, plaintext);
            std::cout << "\n";
            try {
                client.sendMessage(std::stoi(recipStr), plaintext);
            } catch (...) {
                std::cerr << "  Invalid recipient ID.\n";
            }
            pause();
            break;
        }
        case 4: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; pause(); break; }
            std::cout << "\n";
            client.fetchAndDecryptMessages();
            pause();
            break;
        }
        case 5: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; pause(); break; }
            std::string msgId, recipStr;
            std::cout << "\n  Message ID to forward: ";
            std::getline(std::cin, msgId);
            std::cout << "  Recipient user ID: ";
            std::getline(std::cin, recipStr);
            std::cout << "\n";
            try {
                client.forwardMessage(msgId, std::stoi(recipStr));
            } catch (...) {
                std::cerr << "  Invalid recipient ID.\n";
            }
            pause();
            break;
        }
        case 6: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; pause(); break; }
            std::string current, next;
            std::cout << "\n  Current password: ";
            std::getline(std::cin, current);
            std::cout << "  New password: ";
            std::getline(std::cin, next);
            std::cout << "\n";
            client.changePassword(current, next);
            pause();
            break;
        }
        case 7: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; pause(); break; }
            std::string msgId;
            std::cout << "\n  Message ID to download: ";
            std::getline(std::cin, msgId);
            std::cout << "\n";
            client.downloadMessage(msgId);
            pause();
            break;
        }
        case 8: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; pause(); break; }
            std::string msgId, uidStr;
            std::cout << "\n  Message ID: ";
            std::getline(std::cin, msgId);
            std::cout << "  User ID to revoke: ";
            std::getline(std::cin, uidStr);
            std::cout << "\n";
            try {
                client.revokeAccess(msgId, std::stoi(uidStr));
            } catch (...) {
                std::cerr << "  Invalid user ID.\n";
            }
            pause();
            break;
        }
        case 9: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; pause(); break; }
            std::string msgId;
            std::cout << "\n  Message ID to delete: ";
            std::getline(std::cin, msgId);
            std::cout << "\n";
            client.deleteMessage(msgId);
            pause();
            break;
        }
        case 0:
            clearScreen();
            std::cout << "\n  " << DIM << "Goodbye." << RESET << "\n\n";
            return 0;
        default:
            std::cout << "\n  " << YELLOW << "Invalid choice — enter 0–9." << RESET << "\n";
            pause();
            break;
        }
    }

    return 0;
}
