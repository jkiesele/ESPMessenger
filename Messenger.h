#ifndef MESSENGER_H
#define MESSENGER_H

#include <vector>
#include <string>
#include <cstdint>
#include "SecurePacketTransceiver.h"
#include "EncryptionHandler.h"
#include "DataFormats.h"


enum Adresses {
    BROADCAST_ADDRESS = 0xFF,
    SB_RESERVOIR_ADDRESS = 0x00,
    OSMO_CONTROLLER_ADDRESS = 0x01
};

class Messenger {
public:
    

    Messenger(uint8_t ownAddress, SecurePacketTransceiver* transceiver=nullptr);
    ~Messenger(){
        if (ownsTransceiver_) {
            delete transceiver_;
        }
    }

    // Send
    template <class T>
    bool send(uint8_t target, DataFormats::DataType type, T value) const{
        std::vector<uint8_t> data;
        DataFormats::serialize(data, value);
        return sendRaw(target, type, data);
    }
    void begin() {
        transceiver_->begin();
    }

    bool poll();

    // Getters
    DataFormats::DataType getLastDataType() const;
    uint8_t getLastSender() const;

    const std::vector<uint8_t>& getLastPayload() const {
        return lastPayload_;
    }


private:
    constexpr static size_t HEADER_SIZE = 3;
    bool sendRaw(uint8_t target, DataFormats::DataType type, const std::vector<uint8_t>& data) const;

    uint8_t ownAddress_;
    SecurePacketTransceiver* transceiver_;
    bool ownsTransceiver_;
    mutable EncryptionHandler encryptionHandler_;

    uint8_t lastFrom_ = 0;
    DataFormats::DataType lastDataType_ = DataFormats::DataType::UNKNOWN;
    std::vector<uint8_t> lastPayload_;
};

#endif // MESSENGER_H