#include "SecurePacketTransceiver.h"
#include <iostream>
#include <cstring>
#include <LoggingBase.h>

// Initialize static members
SecurePacketTransceiver* SecurePacketTransceiver::instance_ = nullptr;
QueueHandle_t SecurePacketTransceiver::rxQueue_ = nullptr;

SecurePacketTransceiver::SecurePacketTransceiver(BackEnd backend,
    const std::vector<uint32_t> * encryptionKeys)
    : lastStatus_(Status::OK), encryptionHandler_(encryptionKeys), backend_(backend), sendBusy_(false), channel_(-1), lastChan(-1) {
    if (backend_ == BackEnd::ESPNow) {
        if (instance_ != nullptr) {
            gLogger->println("[ERROR] Only one SecurePacketTransceiver allowed in ESPNow mode.");
            abort();
        }
        instance_ = this;
        // Create a queue to hold pointers to std::vector<uint8_t>
        rxQueue_ = xQueueCreate(5, sizeof(std::vector<uint8_t>*));
        if (rxQueue_ == nullptr) {
            gLogger->println("[ERROR] Failed to create rxQueue");
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
    else if (backend_ == BackEnd::TCP) {
        if (tcpClient_.connected()) tcpClient_.stop();
      }
}

void SecurePacketTransceiver::begin() {
    if (backend_ == BackEnd::ESPNow) {
        wifi_mode_t mode;
        esp_wifi_get_mode(&mode);
        if (mode != WIFI_STA && mode != WIFI_AP_STA) {
            gLogger->println("[ERROR] ESP-NOW requires WIFI_STA or WIFI_AP_STA mode.");
            abort();
        }
        if (esp_now_init() != ESP_OK) {
            gLogger->println("[ERROR] Failed to initialize ESP-NOW");
            abort();
        }
        else {
            esp_now_register_recv_cb(onEspNowRecv);
            esp_now_register_send_cb(onEspNowSend);
        }
    }
    else if (backend_ == BackEnd::TCP) {
        // nothing to do here: we connect lazily in send()
      }
}

SecurePacketTransceiver::Status SecurePacketTransceiver::send(const std::vector<uint8_t>& plainPacket, const std::vector<uint8_t>& destAddress) {
    
    if(sendBusy_) 
        return Status::BUSY;

    std::vector<uint8_t> encrypted = encryptionHandler_.encrypt(plainPacket);
    if (backend_ == BackEnd::ESPNow) {
        if (destAddress.size() != 6) {
            gLogger->println("[ERROR] ESPNow destination address must be 6 bytes.");
            lastStatus_ = Status::ERROR;
            return Status::ERROR;
        }

        uint8_t channel;
        wifi_second_chan_t secondary;
        if(channel_ < 0){
            // Get the current channel
            esp_wifi_get_channel(&channel, &secondary);
        }
        else{
            channel = static_cast<uint8_t>(channel_);
        }
        esp_now_peer_info_t peerInfo = {};
        memcpy(peerInfo.peer_addr, destAddress.data(), 6);
        peerInfo.channel = channel;
        bool channelChanged = lastChan != channel;
        peerInfo.ifidx = WIFI_IF_STA;
        peerInfo.encrypt = false;
        if (!esp_now_is_peer_exist(destAddress.data()) || channelChanged) {
            if(esp_now_is_peer_exist(destAddress.data()))//channel changed
                esp_now_del_peer(destAddress.data());
            auto ret = esp_now_add_peer(&peerInfo);
            if (ret != ESP_OK) {
                gLogger->print("[ERROR] Failed to add ESPNow peer, error code: ");
                gLogger->println(ret);
                lastStatus_ = Status::ERROR;
                return Status::ERROR;
            }
            lastChan = channel;
        }
        
        // 3) Store for callback-driven retries
        pendingDest_    = destAddress;
        pendingData_    = encrypted;
        pendingRetries_ = 0;
      
        // 4) Fire the first shot
        esp_err_t result = esp_now_send(pendingDest_.data(),
                     pendingData_.data(),
                     pendingData_.size());
        if (result == ESP_OK){  
            sendBusy_   = true;
            lastStatus_ = Status::SENDING;
            return Status::SENDING;
        }
        else{
            sendBusy_   = false;
            lastStatus_ = Status::ERROR;
            return Status::ERROR;
        }
    }
    else if (backend_ == BackEnd::TCP) {
      // 1) ensure connection
      if (!tcpClient_.connected()) {
        if (!tcpClient_.connect(serverIp_, serverPort_)) {
          gLogger->println("[ERROR] TCP connect failed");
          return Status::ERROR;
        }
      }
      // 2) frame with 2-byte length prefix (big-endian)
      uint16_t len = encrypted.size();
      uint8_t header[2] = { uint8_t(len >> 8), uint8_t(len & 0xFF) };
      if (tcpClient_.write(header, 2) != 2) {
        gLogger->println("[ERROR] TCP write header failed");
        return Status::ERROR;
      }
      // 3) send payload
      if (tcpClient_.write(encrypted.data(), len) != len) {
        gLogger->println("[ERROR] TCP write body failed");
        return Status::ERROR;
      }
      // 4) we consider it “sent” immediately
      return Status::OK;
    }

    return Status::ERROR;
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
    else if (backend_ == BackEnd::TCP) {
      // 1) check if we have at least a 2-byte header
      if (tcpClient_.connected() && tcpClient_.available() >= 2) {
        uint8_t header[2];
        tcpClient_.readBytes(header, 2);
        uint16_t len = (uint16_t(header[0]) << 8) | header[1];

        // 2) wait for full payload
        while (tcpClient_.available() < len) {
          delay(1);
        }
        std::vector<uint8_t> buf(len);
        tcpClient_.readBytes(buf.data(), len);

        // 3) decrypt
        return encryptionHandler_.decrypt(buf, decryptedPacket);
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
        instance_->handleEspNowSend(mac, status);
    }
}

void SecurePacketTransceiver::handleEspNowSend(const uint8_t* mac, esp_now_send_status_t status) {
  if (!sendBusy_) return;  // no packet pending? ignore
  if (memcmp(mac, pendingDest_.data(), 6) != 0) return;

  if (status == ESP_NOW_SEND_SUCCESS) {
    // Got the MAC‐layer ACK — we’re done
    sendBusy_ = false;
    lastStatus_ = Status::OK;
    pendingDest_.clear();
    pendingData_.clear();
  }
  else {
    // No ACK this time
    if (++pendingRetries_ < maxRetries_) {
        esp_err_t err = esp_now_send(pendingDest_.data(),
                   pendingData_.data(),
                   pendingData_.size());
        if (err != ESP_OK) {
          gLogger->print("[ESPNow] retry-send failed code ");
          gLogger->println(err);
        }
    }
    else {
       sendBusy_   = false;
       lastStatus_ = Status::NO_ACK;
       pendingDest_.clear();
       pendingData_.clear();
       gLogger->println("[ESPNow] retry limit reached, dropping packet");
    }
  }
}