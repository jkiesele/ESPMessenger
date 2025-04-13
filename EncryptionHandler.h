#ifndef ENCRYPTION_HANDLER_H
#define ENCRYPTION_HANDLER_H

#include <vector>
#include <cstdint>
#include <cstring>
#include "passwords.h"

class CRC32 {
public:
    static uint32_t calculate(const uint8_t* data, size_t length) {
#ifdef ESP32
        return esp_crc32_le(0, data, length);
#else
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < length; ++i) {
            crc ^= data[i];
            for (uint8_t j = 0; j < 8; ++j) {
                if (crc & 1)
                    crc = (crc >> 1) ^ 0xEDB88320;
                else
                    crc >>= 1;
            }
        }
        return ~crc;
#endif
    }
};

class EncryptionHandler {
public:
    static constexpr size_t CHECKSUM_SIZE = 4;

    EncryptionHandler() : keyIndex_(0) {}

    // Encrypt: appends checksum and XORs everything
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) const {
        std::vector<uint8_t> result = data;

        // Append CRC32 checksum
        uint32_t checksum = CRC32::calculate(data.data(), data.size());
        uint8_t* checksumPtr = reinterpret_cast<uint8_t*>(&checksum);
        result.insert(result.end(), checksumPtr, checksumPtr + CHECKSUM_SIZE);

        // Encrypt in place
        const uint32_t key = secret::encryption_keys[keyIndex_];
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] ^= reinterpret_cast<const uint8_t*>(&key)[i % 4];
        }

        keyIndex_ = (keyIndex_ + 1) % secret::encryption_keys.size();
        return result;
    }

    // Decrypt: XORs, verifies checksum, returns decrypted data if valid
    bool decrypt(const std::vector<uint8_t>& encryptedData, std::vector<uint8_t>& output) const {
        if (encryptedData.size() < CHECKSUM_SIZE) return false;

        for (const uint32_t& key : secret::encryption_keys) {
            std::vector<uint8_t> temp = encryptedData;

            // XOR decrypt
            for (size_t i = 0; i < temp.size(); ++i) {
                temp[i] ^= reinterpret_cast<const uint8_t*>(&key)[i % 4];
            }

            // Separate data and checksum
            size_t dataSize = temp.size() - CHECKSUM_SIZE;
            uint32_t embeddedChecksum;
            std::memcpy(&embeddedChecksum, &temp[dataSize], CHECKSUM_SIZE);

            uint32_t calculatedChecksum = CRC32::calculate(temp.data(), dataSize);

            if (embeddedChecksum == calculatedChecksum) {
                output.assign(temp.begin(), temp.begin() + dataSize);
                return true;
            }
        }

        output.clear();  // Clear if no valid decryption
        return false;
    }

private:
    mutable size_t keyIndex_;
};

#endif // ENCRYPTION_HANDLER_H