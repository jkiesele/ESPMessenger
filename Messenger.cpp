#include "Messenger.h"
#include <cstring>
#include "macAddresses.h"

Messenger::Messenger(uint8_t ownAddress, SecurePacketTransceiver* transceiver)
    : ownAddress_(ownAddress), transceiver_(transceiver) {}

bool Messenger::send(uint8_t target, DataID id, int32_t value) const {
    return sendRaw(target, id, DataType::INT32, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
}

bool Messenger::send(uint8_t target, DataID id, uint32_t value) const {
    return sendRaw(target, id, DataType::UINT32, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
}

bool Messenger::send(uint8_t target, DataID id, float value) const {
    return sendRaw(target, id, DataType::FLOAT32, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
}

bool Messenger::send(uint8_t target, DataID id, const std::vector<int32_t>& values) const {
    return sendRaw(target, id, DataType::V_INT32, reinterpret_cast<const uint8_t*>(values.data()), values.size() * sizeof(int32_t));
}

bool Messenger::send(uint8_t target, DataID id, const std::vector<uint32_t>& values) const {
    return sendRaw(target, id, DataType::V_UINT32, reinterpret_cast<const uint8_t*>(values.data()), values.size() * sizeof(uint32_t));
}

bool Messenger::send(uint8_t target, DataID id, const std::vector<float>& values) const {
    return sendRaw(target, id, DataType::V_FLOAT32, reinterpret_cast<const uint8_t*>(values.data()), values.size() * sizeof(float));
}

bool Messenger::send(uint8_t target, DataID id, const std::string& value) const {
    return sendRaw(target, id, DataType::STRING, reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

bool Messenger::poll() {
    std::vector<uint8_t> decrypted;
    if (!transceiver_->receive(decrypted)) return false;
    if (decrypted.size() < 4) return false;

    if (decrypted[0] != ownAddress_ && decrypted[0] != 0xFF) return false;

    lastFrom_ = decrypted[1];
    lastDataID_ = static_cast<DataID>(decrypted[2]);
    lastDataType_ = static_cast<DataType>(decrypted[3]);
    lastPayload_.assign(decrypted.begin() + 4, decrypted.end());
    return true;
}

Messenger::DataID Messenger::getLastDataID() const {
    return lastDataID_;
}

Messenger::DataType Messenger::getLastDataType() const {
    return lastDataType_;
}

uint8_t Messenger::getLastSender() const {
    return lastFrom_;
}

int32_t Messenger::getDataInt32() const {
    int32_t result;
    std::memcpy(&result, lastPayload_.data(), sizeof(result));
    return result;
}

uint32_t Messenger::getDataUInt32() const {
    uint32_t result;
    std::memcpy(&result, lastPayload_.data(), sizeof(result));
    return result;
}

float Messenger::getDataFloat32() const {
    float result;
    std::memcpy(&result, lastPayload_.data(), sizeof(result));
    return result;
}

std::vector<int32_t> Messenger::getDataVInt32() const {
    size_t n = lastPayload_.size() / sizeof(int32_t);
    return std::vector<int32_t>(reinterpret_cast<const int32_t*>(lastPayload_.data()), 
                                reinterpret_cast<const int32_t*>(lastPayload_.data()) + n);
}

std::vector<uint32_t> Messenger::getDataVUInt32() const {
    size_t n = lastPayload_.size() / sizeof(uint32_t);
    return std::vector<uint32_t>(reinterpret_cast<const uint32_t*>(lastPayload_.data()), 
                                 reinterpret_cast<const uint32_t*>(lastPayload_.data()) + n);
}

std::vector<float> Messenger::getDataVFloat32() const {
    size_t n = lastPayload_.size() / sizeof(float);
    return std::vector<float>(reinterpret_cast<const float*>(lastPayload_.data()), 
                              reinterpret_cast<const float*>(lastPayload_.data()) + n);
}

std::string Messenger::getDataString() const {
    return std::string(lastPayload_.begin(), lastPayload_.end());
}

bool Messenger::sendRaw(uint8_t target, DataID id, DataType type, const uint8_t* data, size_t size) const {
    std::vector<uint8_t> plainPacket;
    plainPacket.push_back(target);
    plainPacket.push_back(ownAddress_);
    plainPacket.push_back(static_cast<uint8_t>(id));
    plainPacket.push_back(static_cast<uint8_t>(type));
    plainPacket.insert(plainPacket.end(), data, data + size);

    if (transceiver_->getBackEnd() == SecurePacketTransceiver::BackEnd::ESPNow) {
        auto it = phonebook::macAddresses.find(target);
        if (it != phonebook::macAddresses.end()) {
            return transceiver_->send(plainPacket, it->second);
        } else {
            // Target MAC not found
            return false;
        }
    } 
    return transceiver_->send(plainPacket);
}