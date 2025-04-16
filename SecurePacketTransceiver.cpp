#include "SecurePacketTransceiver.h"
#include <iostream>
#include <cstring>

#ifdef ESP32
SecurePacketTransceiver* SecurePacketTransceiver::instance_ = nullptr;
#endif

SecurePacketTransceiver::SecurePacketTransceiver(BackEnd backend)
    : backend_(backend), sendBusy_(false) {
#ifdef ESP32
    if (backend_ == BackEnd::ESPNow) {
        if (instance_ != nullptr) {
            Serial.println("[ERROR] Only one SecurePacketTransceiver allowed in ESPNow mode.");
            abort();
        }

        instance_ = this;
    }
#endif
}

SecurePacketTransceiver::~SecurePacketTransceiver() {
#ifdef ESP32
    if (backend_ == BackEnd::ESPNow && instance_ == this) {
        esp_now_unregister_recv_cb();
        esp_now_deinit();
        instance_ = nullptr;
    }
#endif
}

bool SecurePacketTransceiver::send(const std::vector<uint8_t>& plainPacket, const std::vector<uint8_t>& destAddress) {
    std::vector<uint8_t> encrypted = encryptionHandler_.encrypt(plainPacket);

#ifdef ESP32
    if (backend_ == BackEnd::ESPNow) {
        if (destAddress.size() != 6) {
            Serial.println("[ERROR] ESPNow destination address must be 6 bytes.");
            return false;
        }

        //
        uint8_t channel;
        wifi_second_chan_t secondary;
        esp_wifi_get_channel(&channel, &secondary);
        esp_now_peer_info_t peerInfo = {};
        memcpy(peerInfo.peer_addr, destAddress.data(), 6);
        peerInfo.channel = channel;
        peerInfo.ifidx = WIFI_IF_STA; // Set the interface index (or WIFI_IF_AP if applicable)
        peerInfo.encrypt = false;

        if (!esp_now_is_peer_exist(destAddress.data())) {
            auto ret = esp_now_add_peer(&peerInfo);
            if (ret != ESP_OK) {
                Serial.print("[ERROR] Failed to add ESPNow peer, error code: ");
                Serial.print(ret);
                Serial.print("\n");
                return false;
            }
        }
        sendBusy_ = true;
        esp_err_t result = esp_now_send(destAddress.data(), encrypted.data(), encrypted.size());
        return result == ESP_OK;
    }
#endif

    if (backend_ == BackEnd::MOCK) {
        std::cout << "[Mock Send] Sending plain packet: ";
        printVector(plainPacket);
        std::cout << "[Mock Send] Encrypted: ";
        printVector(encrypted);
        buffer_ = encrypted;
        return true;
    }

    return false;
}

bool SecurePacketTransceiver::receive(std::vector<uint8_t>& decryptedPacket) {
#ifdef ESP32
    if (backend_ == BackEnd::ESPNow) {
        if (buffer_.empty()) return false;
        bool success = encryptionHandler_.decrypt(buffer_, decryptedPacket);
        buffer_.clear();
        return success;
    }
#endif

    if (backend_ == BackEnd::MOCK) {
        if (buffer_.empty()) {
            std::cerr << "[Mock Receive] No packet available.\n";
            return false;
        }

        bool success = encryptionHandler_.decrypt(buffer_, decryptedPacket);
        if (success) {
            std::cout << "[Mock Receive] Decryption successful: ";
            printVector(decryptedPacket);
        } else {
            std::cerr << "[Mock Receive] Decryption failed.\n";
        }
        return success;
    }

    return false;
}

SecurePacketTransceiver::BackEnd SecurePacketTransceiver::getBackEnd() const {
    return backend_;
}

void SecurePacketTransceiver::printVector(const std::vector<uint8_t>& data) {
    for (uint8_t byte : data) {
        std::cout << std::hex << static_cast<int>(byte) << ' ';
    }
    std::cout << std::dec << std::endl;
}

#ifdef ESP32
void SecurePacketTransceiver::onEspNowRecv(const uint8_t* mac, const uint8_t* data, int len) {
    if (instance_) {
        instance_->handleEspNowRecv(data, len);
    }
}

void SecurePacketTransceiver::handleEspNowRecv(const uint8_t* data, int len) {
    buffer_.assign(data, data + len);
    Serial.println("[ESPNow] Received data");
}
void SecurePacketTransceiver::onEspNowSend(const uint8_t* mac, esp_now_send_status_t status) {
    if (instance_) {
        instance_->handleEspNowSend(status);
    }
}

void SecurePacketTransceiver::handleEspNowSend(esp_now_send_status_t status) {
    sendBusy_ = false;
}
#endif