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
    

    Messenger(uint8_t ownAddress, 
             const std::vector<std::vector<uint8_t>> * macAdresses=0,
             const std::vector<uint32_t> * encryptionKeys=0,
             SecurePacketTransceiver* transceiver=nullptr);
    ~Messenger(){
        if (ownsTransceiver_) {
            delete transceiver_;
        }
    }

    void begin() {
        transceiver_->begin();
    }

    SecurePacketTransceiver* getTransceiver() {
        return transceiver_;
    }

    // Send
    template <class T>
    bool send(uint8_t target, DataFormats::DataType type, T value) const{
        std::vector<uint8_t> data;
        DataFormats::serialize(data, value);
        return sendRaw(target, type, data);
    }
    bool isSendBusy() const {
        return transceiver_->isSendBusy();
    }
    
    // Receive functions. Their order here means something and should be used like this in code.

    // use this to poll for new messages
    // returns true if a new message was received
    bool poll();

    // returns true if a new message was received upon last call of poll
    bool hasNewData() const {
        return hasNewData_;
    }

    // is this data I want to handle?
    DataFormats::DataType getLastDataType() const;
    uint8_t getLastSender() const;

    const std::vector<uint8_t>& getLastPayload() const {
        return lastPayload_;
    }

    // clears the buffer once the message has been handled
    void clearForNewPacket() {
        lastFrom_ = 0;
        lastDataType_ = DataFormats::DataType::UNKNOWN;
        lastPayload_.clear();
        hasNewData_ = false;
    }


private:
    constexpr static size_t HEADER_SIZE = 3;
    bool sendRaw(uint8_t target, DataFormats::DataType type, const std::vector<uint8_t>& data) const;

    uint8_t ownAddress_;
    SecurePacketTransceiver* transceiver_;
    bool ownsTransceiver_;

    uint8_t lastFrom_ = 0;
    DataFormats::DataType lastDataType_ = DataFormats::DataType::UNKNOWN;
    std::vector<uint8_t> lastPayload_;
    bool hasNewData_ = false;
    const std::vector<std::vector<uint8_t>> * macAdresses_;
};

#endif // MESSENGER_H