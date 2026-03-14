#ifndef ENCRYPTION_HANDLER_H
#define ENCRYPTION_HANDLER_H

#include <vector>
#include <cstdint>
#include <cstdlib> // for rand()

class CRC32 {
public:
    static uint32_t calculate(const uint8_t* data, size_t length);
};

class EncryptionHandler {
public:
    static constexpr size_t CHECKSUM_SIZE = 4;

    EncryptionHandler(const std::vector<uint32_t> * encryptionKeys);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) const;
    bool decrypt(const std::vector<uint8_t>& encryptedData, std::vector<uint8_t>& output) const;

private:
    void randomizeKeyIndex() const {
        keyIndex_ = rand() % encryptionKeys_->size();
    }
    mutable size_t keyIndex_;
    const std::vector<uint32_t> * encryptionKeys_;
};

#endif // ENCRYPTION_HANDLER_H