#include <iostream>
#include <iomanip>
#include <filesystem>
#include <string>
#include <vector>
#include <cstdlib>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>
#include "Client.h"
#include "CryptoUtils.h"
#include "Message.h"

// ANSI colour codes
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

static std::string readPassword(const char* prompt) {
    std::cout << prompt << std::flush;
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::string pw;
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    return pw;
}

static void waitForEnter() {
    std::cout << "\n" << DIM << "  Press Enter to continue..." << RESET << std::flush;
    std::string dummy;
    std::getline(std::cin, dummy);
}

// Truncate a string to maxLen chars, appending "…" if cut
static std::string trunc(const std::string& s, size_t maxLen) {
    if (s.size() <= maxLen) return s;
    return s.substr(0, maxLen - 1) + "\xe2\x80\xa6"; // UTF-8 ellipsis
}

// Extract HH:MM from an ISO-8601 sentAt string ("2026-06-03T14:32:00.000Z")
static std::string shortTime(const std::string& sentAt) {
    if (sentAt.size() >= 16) return sentAt.substr(11, 5);
    return sentAt;
}

// Draw the inbox panel — shown on every logged-in screen and before any
// action that needs a message ID or user ID, so those values are always visible.
static void drawInbox(const std::vector<Message>& msgs, int myUserId) {
    const std::string myId = std::to_string(myUserId);

    std::cout << "  " << BOLD << "── Inbox ";
    if (msgs.empty()) {
        std::cout << RESET << DIM << "(empty — press 4 to refresh)" << RESET << "\n\n";
        return;
    }
    std::cout << "(" << msgs.size() << " message" << (msgs.size() != 1 ? "s" : "") << ")"
              << RESET << "\n";

    // Header row
    std::cout << "  " << BOLD
              << std::left
              << std::setw(5)  << "ID"
              << std::setw(6)  << "From"
              << std::setw(3)  << "→"
              << std::setw(6)  << "To"
              << std::setw(34) << "Preview"
              << "Time"
              << RESET << "\n";
    std::cout << "  " << std::string(58, '-') << "\n";

    for (const auto& m : msgs) {
        const bool mine = (m.getSender() == myId);
        const std::string from    = mine ? "you" : m.getSender();
        const std::string to      = mine ? m.getRecipient() : "you";
        const std::string preview = trunc(m.getPlaintext(), 32);
        const std::string when    = shortTime(m.getSentAt());

        if (mine)
            std::cout << GRAY;
        else
            std::cout << GREEN;

        std::cout << "  "
                  << std::left
                  << std::setw(5)  << m.getId()
                  << std::setw(6)  << from
                  << std::setw(3)  << "\xe2\x86\x92" // UTF-8 →
                  << std::setw(6)  << to
                  << std::setw(34) << preview
                  << when
                  << RESET << "\n";
    }
    std::cout << "  " << std::string(58, '-') << "\n\n";
}

// Draw the full screen: header + inbox panel (if logged in) + menu
static void drawScreen(bool loggedIn, int userId, const std::vector<Message>& inbox) {
    clearScreen();

    std::cout << "\n  " << BOLD << CYAN << "Rizzie-Hellmans" << RESET
              << "  —  Secure E2E Messaging\n";
    std::cout << "  " << std::string(58, '=') << "\n";

    if (loggedIn) {
        std::cout << "  " << GREEN << "● Logged in  "
                  << RESET << GREEN << "(user id: " << BOLD << userId << RESET << GREEN << ")" << RESET << "\n\n";
        drawInbox(inbox, userId);
    } else {
        std::cout << "  " << YELLOW << "○  Not logged in" << RESET << "\n\n";
    }

    // Menu — gray out login-required options when not logged in
    auto item = [&](const char* num, const char* label, bool needsLogin) {
        if (needsLogin && !loggedIn)
            std::cout << "  " << GRAY << num << "  " << label << RESET << "\n";
        else
            std::cout << "  " << BOLD << CYAN << num << RESET << "  " << label << "\n";
    };

    item("1", "Register",         false);
    item("2", "Login",            false);
    item("3", "Send message",     true);
    item("4", "Refresh inbox",    true);
    item("5", "Forward message",  true);
    item("6", "Change password",  true);
    item("7", "Download message", true);
    item("8", "Revoke access",    true);
    item("9", "Delete message",   true);
    std::cout << "  " << DIM << "0  Quit" << RESET << "\n";

    std::cout << "\n  " << std::string(58, '=') << "\n";
    std::cout << "\n  Choice: ";
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialise libsodium\n";
        return 1;
    }

    clearScreen();
    std::cout << "\n  " << BOLD << CYAN << "Rizzie-Hellmans" << RESET << "  —  Key Setup\n\n";
    std::string passphrase = readPassword("  Enter passphrase: ");
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
    waitForEnter();

    Client client("https://rizzie-hellmans.theburkenator.com");
    client.setKeyPair(myPublicKey, myPrivateKey);

    while (true) {
        std::vector<Message> inbox = client.getCachedMessages();
        drawScreen(client.isLoggedIn(), client.getUserId(), inbox);

        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        int choice = -1;
        try { choice = std::stoi(line); } catch (...) {}

        switch (choice) {
        case 1: {
            std::string username;
            std::cout << "\n  Username: ";
            std::getline(std::cin, username);
            std::string password = readPassword("  Password: ");
            std::cout << "\n";
            client.registerUser(username, password);
            waitForEnter();
            break;
        }
        case 2: {
            std::string username;
            std::cout << "\n  Username: ";
            std::getline(std::cin, username);
            std::string password = readPassword("  Password: ");
            std::cout << "\n";
            client.login(username, password);
            waitForEnter();
            break;
        }
        case 3: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; waitForEnter(); break; }
            // Show inbox so user can see recipient IDs
            drawInbox(client.getCachedMessages(), client.getUserId());
            std::string recipStr, plaintext;
            std::cout << "  Recipient user ID: ";
            std::getline(std::cin, recipStr);
            std::cout << "  Message: ";
            std::getline(std::cin, plaintext);
            std::cout << "\n";
            try {
                client.sendMessage(std::stoi(recipStr), plaintext);
            } catch (...) {
                std::cerr << "  Invalid recipient ID.\n";
            }
            waitForEnter();
            break;
        }
        case 4: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; waitForEnter(); break; }
            std::cout << "\n";
            client.fetchAndDecryptMessages();
            waitForEnter();
            break;
        }
        case 5: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; waitForEnter(); break; }
            // Show inbox so user can see message IDs and recipient user IDs at a glance
            drawInbox(client.getCachedMessages(), client.getUserId());
            std::string msgId, recipStr;
            std::cout << "  Message ID to forward: ";
            std::getline(std::cin, msgId);
            std::cout << "  Recipient user ID:     ";
            std::getline(std::cin, recipStr);
            std::cout << "\n";
            try {
                client.forwardMessage(msgId, std::stoi(recipStr));
            } catch (...) {
                std::cerr << "  Invalid recipient ID.\n";
            }
            waitForEnter();
            break;
        }
        case 6: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; waitForEnter(); break; }
            std::string current = readPassword("\n  Current password: ");
            std::string next    = readPassword("  New password:     ");
            std::cout << "\n";
            client.changePassword(current, next);
            waitForEnter();
            break;
        }
        case 7: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; waitForEnter(); break; }
            // Show inbox so user can pick a message ID to download
            drawInbox(client.getCachedMessages(), client.getUserId());
            std::string msgId;
            std::cout << "  Message ID to download: ";
            std::getline(std::cin, msgId);
            std::cout << "\n";
            client.downloadMessage(msgId);
            waitForEnter();
            break;
        }
        case 8: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; waitForEnter(); break; }
            // Show inbox so user can see message IDs and the user IDs they shared with
            drawInbox(client.getCachedMessages(), client.getUserId());
            std::string msgId, uidStr;
            std::cout << "  Message ID:        ";
            std::getline(std::cin, msgId);
            std::cout << "  User ID to revoke: ";
            std::getline(std::cin, uidStr);
            std::cout << "\n";
            try {
                client.revokeAccess(msgId, std::stoi(uidStr));
            } catch (...) {
                std::cerr << "  Invalid user ID.\n";
            }
            waitForEnter();
            break;
        }
        case 9: {
            if (!client.isLoggedIn()) { std::cout << "\n  " << YELLOW << "Please login first." << RESET << "\n"; waitForEnter(); break; }
            // Show inbox so user can see message IDs before deleting
            drawInbox(client.getCachedMessages(), client.getUserId());
            std::string msgId;
            std::cout << "  Message ID to delete: ";
            std::getline(std::cin, msgId);
            std::cout << "\n";
            client.deleteMessage(msgId);
            waitForEnter();
            break;
        }
        case 0:
            clearScreen();
            std::cout << "\n  " << DIM << "Goodbye." << RESET << "\n\n";
            return 0;
        default:
            std::cout << "\n  " << YELLOW << "Invalid choice — enter 0–9." << RESET << "\n";
            waitForEnter();
            break;
        }
    }

    return 0;
}
