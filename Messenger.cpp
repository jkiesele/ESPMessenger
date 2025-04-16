#include "Messenger.h"
#include <cstring>
#include "macAddresses.h"

Messenger::Messenger(uint8_t ownAddress, SecurePacketTransceiver* transceiver)
    : ownAddress_(ownAddress), transceiver_(transceiver) {
        if(transceiver == nullptr) {
            transceiver_ = new SecurePacketTransceiver(SecurePacketTransceiver::BackEnd::ESPNow);
            ownsTransceiver_ = true;
        } else {
            ownsTransceiver_ = false;
        }
    }

bool Messenger::poll() {
    std::vector<uint8_t> decrypted;
    if (!transceiver_->receive(decrypted)) return false;
    // HEADER_SIZE: target, ownAddress, type
    if (decrypted.size() < HEADER_SIZE) return false;

    if (decrypted[0] != ownAddress_ && decrypted[0] != 0xFF) return false;

    lastFrom_ = decrypted[1];
    lastDataType_ = static_cast<DataFormats::DataType>(decrypted[2]);
    lastPayload_.assign(decrypted.begin() + HEADER_SIZE, decrypted.end());
    return true;
}

DataFormats::DataType Messenger::getLastDataType() const {
    return lastDataType_;
}

uint8_t Messenger::getLastSender() const {
    return lastFrom_;
}

bool Messenger::sendRaw(uint8_t target, DataFormats::DataType type, const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> plainPacket;
    // HEADER_SIZE: target, ownAddress, type
    plainPacket.reserve(HEADER_SIZE + data.size());
    plainPacket.push_back(target);
    plainPacket.push_back(ownAddress_);
    plainPacket.push_back(static_cast<uint8_t>(type));
    plainPacket.insert(plainPacket.end(), data.begin(), data.end());

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