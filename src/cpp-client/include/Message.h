#pragma once
#include <string>

class Message {
public:
    Message(const std::string& id, const std::string& sender,
            const std::string& recipient, const std::string& enc,
            const std::string& ciphertext, const std::string& plaintext,
            const std::string& txHash, const std::string& sentAt)
        : id(id), sender(sender), recipient(recipient), enc(enc),
          ciphertext(ciphertext), plaintext(plaintext),
          txHash(txHash), sentAt(sentAt) {}

    const std::string& getId()         const { return id; }
    const std::string& getSender()     const { return sender; }
    const std::string& getRecipient()  const { return recipient; }
    const std::string& getEnc()        const { return enc; }
    const std::string& getCiphertext() const { return ciphertext; }
    const std::string& getPlaintext()  const { return plaintext; }
    const std::string& getTxHash()     const { return txHash; }
    const std::string& getSentAt()     const { return sentAt; }

private:
    std::string id, sender, recipient, enc, ciphertext, plaintext, txHash, sentAt;
};
