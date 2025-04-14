#ifndef ENCRYPTION_HANDLER_H
#define ENCRYPTION_HANDLER_H

#include <vector>
#include <cstdint>

class CRC32 {
public:
    static uint32_t calculate(const uint8_t* data, size_t length);
};

class EncryptionHandler {
public:
    static constexpr size_t CHECKSUM_SIZE = 4;

    EncryptionHandler();

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) const;
    bool decrypt(const std::vector<uint8_t>& encryptedData, std::vector<uint8_t>& output) const;

private:
    mutable size_t keyIndex_;
};

#endif // ENCRYPTION_HANDLER_H