#include "EncryptionHandler.h"
#include "passwords.h"
#include <cstring>  // for std::memcpy

#ifdef ESP32
#include "esp_crc.h"
#endif

// ---------------- CRC32 Implementation ----------------

uint32_t CRC32::calculate(const uint8_t* data, size_t length) {
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

// ---------------- EncryptionHandler Implementation ----------------

EncryptionHandler::EncryptionHandler() : keyIndex_(0) {}

std::vector<uint8_t> EncryptionHandler::encrypt(const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> result = data;

    uint32_t checksum = CRC32::calculate(data.data(), data.size());
    const uint8_t* checksumPtr = reinterpret_cast<const uint8_t*>(&checksum);
    result.insert(result.end(), checksumPtr, checksumPtr + CHECKSUM_SIZE);

    const uint32_t key = secret::encryption_keys[keyIndex_];
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= reinterpret_cast<const uint8_t*>(&key)[i % 4];
    }

    keyIndex_ = (keyIndex_ + 1) % secret::encryption_keys.size();
    return result;
}

bool EncryptionHandler::decrypt(const std::vector<uint8_t>& encryptedData, std::vector<uint8_t>& output) const {
    if (encryptedData.size() < CHECKSUM_SIZE) return false;

    for (const uint32_t& key : secret::encryption_keys) {
        std::vector<uint8_t> temp = encryptedData;

        for (size_t i = 0; i < temp.size(); ++i) {
            temp[i] ^= reinterpret_cast<const uint8_t*>(&key)[i % 4];
        }

        size_t dataSize = temp.size() - CHECKSUM_SIZE;
        uint32_t embeddedChecksum;
        std::memcpy(&embeddedChecksum, &temp[dataSize], CHECKSUM_SIZE);

        uint32_t calculatedChecksum = CRC32::calculate(temp.data(), dataSize);
        if (embeddedChecksum == calculatedChecksum) {
            output.assign(temp.begin(), temp.begin() + dataSize);
            return true;
        }
    }

    output.clear();
    return false;
}