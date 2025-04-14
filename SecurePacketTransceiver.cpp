#include "SecurePacketTransceiver.h"
#include <iostream>
#include <cstring>

#ifdef ESP32
SecurePacketTransceiver* SecurePacketTransceiver::instance_ = nullptr;
#endif

SecurePacketTransceiver::SecurePacketTransceiver(BackEnd backend)
    : backend_(backend) {
#ifdef ESP32
    if (backend_ == BackEnd::ESPNow) {
        if (instance_ != nullptr) {
            Serial.println("[ERROR] Only one SecurePacketTransceiver allowed in ESPNow mode.");
            abort();
        }

        wifi_mode_t mode;
        esp_wifi_get_mode(&mode);
        if (mode != WIFI_STA && mode != WIFI_AP_STA) {
            Serial.println("[ERROR] ESP-NOW requires WIFI_STA or WIFI_AP_STA mode.");
            abort();
        }

        if (esp_now_init() != ESP_OK) {
            Serial.println("[ERROR] Failed to initialize ESP-NOW");
            abort();
        }

        instance_ = this;
        esp_now_register_recv_cb(onEspNowRecv);
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

        esp_now_peer_info_t peerInfo = {};
        memcpy(peerInfo.peer_addr, destAddress.data(), 6);
        peerInfo.channel = 0;
        peerInfo.encrypt = false;

        if (!esp_now_is_peer_exist(destAddress.data())) {
            if (esp_now_add_peer(&peerInfo) != ESP_OK) {
                Serial.println("[ERROR] Failed to add ESPNow peer");
                return false;
            }
        }

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
}
#endif