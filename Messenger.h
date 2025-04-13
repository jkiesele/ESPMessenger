#ifndef MESSENGER_H
#define MESSENGER_H

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cstring>
#include "EncryptionHandler.h"
#include "SecurePacketTransceiver.h"
#include "macAddresses.h" // Assuming this is a header file for the phonebook

class Messenger {
public:
    enum class DataID : uint8_t {
        SENSOR_DATA = 0x01,
        LOG_DATA    = 0x02
        // extend as needed
    };

    enum class DataType : uint8_t {
        INT32      = 0x01,
        UINT32     = 0x02,
        FLOAT32    = 0x03,
        V_INT32    = 0x04,
        V_UINT32   = 0x05,
        V_FLOAT32  = 0x06,
        STRING     = 0x07
    };

    Messenger(uint8_t ownAddress, SecurePacketTransceiver* transceiver)
        : ownAddress_(ownAddress), transceiver_(transceiver) {}

    // Send overloads
    void send(uint8_t target, DataID id, int32_t value) const {
        sendRaw(target, id, DataType::INT32, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
    }

    void send(uint8_t target, DataID id, uint32_t value) const {
        sendRaw(target, id, DataType::UINT32, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
    }

    void send(uint8_t target, DataID id, float value) const {
        sendRaw(target, id, DataType::FLOAT32, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
    }

    void send(uint8_t target, DataID id, const std::vector<int32_t>& values) const {
        sendRaw(target, id, DataType::V_INT32, reinterpret_cast<const uint8_t*>(values.data()), values.size() * sizeof(int32_t));
    }

    void send(uint8_t target, DataID id, const std::vector<uint32_t>& values) const {
        sendRaw(target, id, DataType::V_UINT32, reinterpret_cast<const uint8_t*>(values.data()), values.size() * sizeof(uint32_t));
    }

    void send(uint8_t target, DataID id, const std::vector<float>& values) const {
        sendRaw(target, id, DataType::V_FLOAT32, reinterpret_cast<const uint8_t*>(values.data()), values.size() * sizeof(float));
    }

    void send(uint8_t target, DataID id, const std::string& value) const {
        sendRaw(target, id, DataType::STRING, reinterpret_cast<const uint8_t*>(value.data()), value.size());
    }

    // Receiver call
    bool poll() {
        std::vector<uint8_t> decrypted;
        if (!transceiver_->receive(decrypted)) return false;
    
        if (decrypted.size() < 4) return false;

        if (decrypted[0] != ownAddress_ && decrypted[0] != 0xFF) return false; // 0xFF is broadcast
    
        // Parse header from decrypted packet
        lastFrom_     = decrypted[1];
        lastDataID_   = static_cast<DataID>(decrypted[2]);
        lastDataType_ = static_cast<DataType>(decrypted[3]);
    
        // Store payload
        lastPayload_.assign(decrypted.begin() + 4, decrypted.end());
        return true;
    }

    // Accessors
    DataID getLastDataID() const { return lastDataID_; }
    DataType getLastDataType() const { return lastDataType_; }
    uint8_t getLastSender() const { return lastFrom_; }

    // Type-safe access to decoded data
    int32_t getDataInt32() const {
        int32_t result;
        std::memcpy(&result, lastPayload_.data(), sizeof(result));
        return result;
    }

    uint32_t getDataUInt32() const {
        uint32_t result;
        std::memcpy(&result, lastPayload_.data(), sizeof(result));
        return result;
    }

    float getDataFloat32() const {
        float result;
        std::memcpy(&result, lastPayload_.data(), sizeof(result));
        return result;
    }

    std::vector<int32_t> getDataVInt32() const {
        size_t n = lastPayload_.size() / sizeof(int32_t);
        return std::vector<int32_t>(reinterpret_cast<const int32_t*>(lastPayload_.data()), 
                                    reinterpret_cast<const int32_t*>(lastPayload_.data()) + n);
    }

    std::vector<uint32_t> getDataVUInt32() const {
        size_t n = lastPayload_.size() / sizeof(uint32_t);
        return std::vector<uint32_t>(reinterpret_cast<const uint32_t*>(lastPayload_.data()), 
                                     reinterpret_cast<const uint32_t*>(lastPayload_.data()) + n);
    }

    std::vector<float> getDataVFloat32() const {
        size_t n = lastPayload_.size() / sizeof(float);
        return std::vector<float>(reinterpret_cast<const float*>(lastPayload_.data()), 
                                  reinterpret_cast<const float*>(lastPayload_.data()) + n);
    }

    std::string getDataString() const {
        return std::string(lastPayload_.begin(), lastPayload_.end());
    }

private:
    void sendRaw(uint8_t target, DataID id, DataType type, const uint8_t* data, size_t size) const {
        std::vector<uint8_t> plainPacket;
    
        plainPacket.push_back(target);         // Address
        plainPacket.push_back(ownAddress_);    // From
        plainPacket.push_back(static_cast<uint8_t>(id));
        plainPacket.push_back(static_cast<uint8_t>(type));
        plainPacket.insert(plainPacket.end(), data, data + size);
    
        if(transceiver_->getBackEnd() == SecurePacketTransceiver::BackEnd::ESPNow) {
            //get mac address from phonebook
            auto it = phonebook::macAddresses.find(target);
            if (it != phonebook::macAddresses.end()) {
                std::vector<uint8_t> macAddress = it->second;
                transceiver_->send(plainPacket, macAddress);
            } else {
                // Handle error: target address not found in phonebook
                return;
            }
        }
        else{
            transceiver_->send(plainPacket);
        }
    }

    uint8_t ownAddress_;
    SecurePacketTransceiver* transceiver_;
    mutable EncryptionHandler encryptionHandler_;

    // Cached last received
    uint8_t lastFrom_ = 0;
    DataID lastDataID_ = DataID::SENSOR_DATA;
    DataType lastDataType_ = DataType::INT32;
    std::vector<uint8_t> lastPayload_;
};

#endif // MESSENGER_H