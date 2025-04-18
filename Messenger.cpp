#include "Messenger.h"
#include <LoggingBase.h>
#include <cstring>

Messenger::Messenger(uint8_t ownAddress, SecurePacketTransceiver* transceiver,
                    const std::vector<std::vector<uint8_t>> * macAdresses)
    : ownAddress_(ownAddress), transceiver_(transceiver), macAdresses_(macAdresses) {
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
    hasNewData_ = true;
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
        //see if we find the mac address in the phonebook (vector)
        size_t index = target;
        if( macAdresses_ == nullptr){
            gLogger->println("[Messenger ERROR] No mac address phonebook available");
            return false;
        }
        if (index >= macAdresses_->size()) {
            gLogger->println("[Messenger ERROR] Invalid target address");
            return false;
        }
        const std::vector<uint8_t>& macAddress = macAdresses_->at(index);
        if (macAddress.empty()) {
            gLogger->println("[Messenger ERROR] No MAC address found for target");
            return false;
        }
        if (macAddress.size() != 6) {
            gLogger->println("[Messenger ERROR] Invalid MAC address size");
            return false;
        }
        // Send the packet to the target address
        if (!transceiver_->send(plainPacket, macAddress)) {
            gLogger->println("[Messenger ERROR] Failed to send packet");
            return false;
        }
        return true;
    } 
    return transceiver_->send(plainPacket);
}