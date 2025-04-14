#ifndef MESSENGER_H
#define MESSENGER_H

#include <vector>
#include <string>
#include <cstdint>
#include "SecurePacketTransceiver.h"
#include "EncryptionHandler.h"
#include "macAddresses.h"

class Messenger {
public:
    enum class DataID : uint8_t {
        SENSOR_DATA = 0x01,
        LOG_DATA    = 0x02
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

    Messenger(uint8_t ownAddress, SecurePacketTransceiver* transceiver);

    // Sender overloads
    void send(uint8_t target, DataID id, int32_t value) const;
    void send(uint8_t target, DataID id, uint32_t value) const;
    void send(uint8_t target, DataID id, float value) const;
    void send(uint8_t target, DataID id, const std::vector<int32_t>& values) const;
    void send(uint8_t target, DataID id, const std::vector<uint32_t>& values) const;
    void send(uint8_t target, DataID id, const std::vector<float>& values) const;
    void send(uint8_t target, DataID id, const std::string& value) const;

    bool poll();

    // Getters
    DataID getLastDataID() const;
    DataType getLastDataType() const;
    uint8_t getLastSender() const;

    // Typed access to payload
    int32_t getDataInt32() const;
    uint32_t getDataUInt32() const;
    float getDataFloat32() const;
    std::vector<int32_t> getDataVInt32() const;
    std::vector<uint32_t> getDataVUInt32() const;
    std::vector<float> getDataVFloat32() const;
    std::string getDataString() const;

private:
    void sendRaw(uint8_t target, DataID id, DataType type, const uint8_t* data, size_t size) const;

    uint8_t ownAddress_;
    SecurePacketTransceiver* transceiver_;
    mutable EncryptionHandler encryptionHandler_;

    uint8_t lastFrom_ = 0;
    DataID lastDataID_ = DataID::SENSOR_DATA;
    DataType lastDataType_ = DataType::INT32;
    std::vector<uint8_t> lastPayload_;
};

#endif // MESSENGER_H