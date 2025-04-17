#include "SecurePacketTransceiver.h"
#include <iostream>
#include <cstring>

// Initialize static members
SecurePacketTransceiver* SecurePacketTransceiver::instance_ = nullptr;
QueueHandle_t SecurePacketTransceiver::rxQueue_ = nullptr;

SecurePacketTransceiver::SecurePacketTransceiver(BackEnd backend)
    : backend_(backend), sendBusy_(false) {
    if (backend_ == BackEnd::ESPNow) {
        if (instance_ != nullptr) {
            Serial.println("[ERROR] Only one SecurePacketTransceiver allowed in ESPNow mode.");
            abort();
        }
        instance_ = this;
        // Create a queue to hold pointers to std::vector<uint8_t>
        rxQueue_ = xQueueCreate(5, sizeof(std::vector<uint8_t>*));
        if (rxQueue_ == nullptr) {
            Serial.println("[ERROR] Failed to create rxQueue");
            abort();
        }
    }
}

SecurePacketTransceiver::~SecurePacketTransceiver() {
    if (backend_ == BackEnd::ESPNow && instance_ == this) {
        esp_now_unregister_recv_cb();
        esp_now_unregister_send_cb();
        esp_now_deinit();
        instance_ = nullptr;
        if (rxQueue_ != nullptr) {
            vQueueDelete(rxQueue_);
            rxQueue_ = nullptr;
        }
    }
}

void SecurePacketTransceiver::begin() {
    if (backend_ == BackEnd::ESPNow) {
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
        else {
            esp_now_register_recv_cb(onEspNowRecv);
            esp_now_register_send_cb(onEspNowSend);
        }
    }
}

bool SecurePacketTransceiver::send(const std::vector<uint8_t>& plainPacket, const std::vector<uint8_t>& destAddress) {
    std::vector<uint8_t> encrypted = encryptionHandler_.encrypt(plainPacket);
    if (backend_ == BackEnd::ESPNow) {
        if (destAddress.size() != 6) {
            Serial.println("[ERROR] ESPNow destination address must be 6 bytes.");
            return false;
        }
        uint8_t channel;
        wifi_second_chan_t secondary;
        esp_wifi_get_channel(&channel, &secondary);
        esp_now_peer_info_t peerInfo = {};
        memcpy(peerInfo.peer_addr, destAddress.data(), 6);
        peerInfo.channel = channel;
        peerInfo.ifidx = WIFI_IF_STA;
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
    return false;
}

bool SecurePacketTransceiver::receive(std::vector<uint8_t>& decryptedPacket) {
    if (backend_ == BackEnd::ESPNow) {
        // Try to receive a pointer from the queue (non-blocking)
        std::vector<uint8_t>* pData = nullptr;
        if (xQueueReceive(rxQueue_, &pData, 0) == pdTRUE && pData != nullptr) {
            bool success = encryptionHandler_.decrypt(*pData, decryptedPacket);
            delete pData;  // Free the dynamically allocated vector
            return success;
        }
        return false;
    }
    return false;
}

SecurePacketTransceiver::BackEnd SecurePacketTransceiver::getBackEnd() const {
    return backend_;
}

void SecurePacketTransceiver::onEspNowRecv(const uint8_t* mac, const uint8_t* data, int len) {
    if (instance_) {
        instance_->handleEspNowRecv(data, len);
    }
}

void SecurePacketTransceiver::handleEspNowRecv(const uint8_t* data, int len) {
    // Allocate a new vector to hold the received data.
    std::vector<uint8_t>* pPacket = new std::vector<uint8_t>(data, data + len);
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    if (rxQueue_ != nullptr) {
        xQueueSendFromISR(rxQueue_, &pPacket, &xHigherPriorityTaskWoken);
    }
    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

void SecurePacketTransceiver::onEspNowSend(const uint8_t* mac, esp_now_send_status_t status) {
    if (instance_) {
        instance_->handleEspNowSend(status);
    }
}

void SecurePacketTransceiver::handleEspNowSend(esp_now_send_status_t status) {
    sendBusy_ = false;
}