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
#include "freertos/semphr.h"
#include "freertos/queue.h"  // for queue

class SecurePacketTransceiver {
public:
    enum class BackEnd {
        MOCK,
        ESPNow,
        TCP
    };

    SecurePacketTransceiver(BackEnd backend = BackEnd::MOCK);
    ~SecurePacketTransceiver();

    void begin();
    bool send(const std::vector<uint8_t>& plainPacket, const std::vector<uint8_t>& destAddress = {});
    bool receive(std::vector<uint8_t>& decryptedPacket);
    BackEnd getBackEnd() const;

private:
    EncryptionHandler encryptionHandler_;
    BackEnd backend_;

    void printVector(const std::vector<uint8_t>& data);

    static SecurePacketTransceiver* instance_;
    static void onEspNowRecv(const uint8_t* mac, const uint8_t* data, int len);
    void handleEspNowRecv(const uint8_t* data, int len);
    static void onEspNowSend(const uint8_t* mac, esp_now_send_status_t status);
    void handleEspNowSend(esp_now_send_status_t status);
    static portMUX_TYPE bufferMutex_;

    std::atomic<bool>  sendBusy_;
    // Remove the class member "buffer_"
    // Instead, add a FreeRTOS queue for received data
    static QueueHandle_t rxQueue_; // Queue of pointers to std::vector<uint8_t>

};

#endif // SECURE_PACKET_TRANSCEIVER_H