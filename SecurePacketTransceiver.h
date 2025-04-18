#ifndef SECURE_PACKET_TRANSCEIVER_H
#define SECURE_PACKET_TRANSCEIVER_H

#include <vector>
#include <cstdint>
#include "EncryptionHandler.h"
#include <atomic>

#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"  // for queue

class SecurePacketTransceiver {
public:
    enum class BackEnd {
        MOCK,
        ESPNow,
        TCP
    };

    SecurePacketTransceiver(BackEnd backend = BackEnd::MOCK, 
        const std::vector<uint32_t> * encryptionKeys=0);
    ~SecurePacketTransceiver();

    void begin();
    bool send(const std::vector<uint8_t>& plainPacket, const std::vector<uint8_t>& destAddress = {});
    bool receive(std::vector<uint8_t>& decryptedPacket);
    bool isSendBusy() const { return sendBusy_; }
    BackEnd getBackEnd() const;

private:
    EncryptionHandler encryptionHandler_;
    BackEnd backend_;

    static SecurePacketTransceiver* instance_;
    static void onEspNowRecv(const uint8_t* mac, const uint8_t* data, int len);
    void handleEspNowRecv(const uint8_t* data, int len);
    static void onEspNowSend(const uint8_t* mac, esp_now_send_status_t status);
    void handleEspNowSend(esp_now_send_status_t status);

    // Remove persistent buffer and mutex
    static QueueHandle_t rxQueue_; // Queue of pointers to std::vector<uint8_t>

    std::atomic<bool> sendBusy_;
};

#endif // SECURE_PACKET_TRANSCEIVER_H