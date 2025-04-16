#ifndef SECURE_PACKET_TRANSCEIVER_H
#define SECURE_PACKET_TRANSCEIVER_H

#include <vector>
#include <cstdint>
#include "EncryptionHandler.h"

#ifdef ESP32
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#endif

class SecurePacketTransceiver {
public:
    enum class BackEnd {
        MOCK,
        ESPNow,
        TCP
    };

    SecurePacketTransceiver(BackEnd backend = BackEnd::MOCK);
    ~SecurePacketTransceiver();

    void begin() {
        // Initialization code if needed
        if(backend_ == BackEnd::ESPNow) {
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

            #ifdef ESP32
            if (esp_now_init() != ESP_OK) {
                Serial.println("[ERROR] Failed to initialize ESP-NOW");
                abort();
            }
            else{
                esp_now_register_recv_cb(onEspNowRecv);
            }
            #endif
        }


        
    }
    bool send(const std::vector<uint8_t>& plainPacket, const std::vector<uint8_t>& destAddress = {});
    bool receive(std::vector<uint8_t>& decryptedPacket);
    BackEnd getBackEnd() const;

private:
    EncryptionHandler encryptionHandler_;
    BackEnd backend_;
    std::vector<uint8_t> buffer_;

    void printVector(const std::vector<uint8_t>& data);

#ifdef ESP32
    static SecurePacketTransceiver* instance_;
    static void onEspNowRecv(const uint8_t* mac, const uint8_t* data, int len);
    void handleEspNowRecv(const uint8_t* data, int len);
#endif
};

#endif // SECURE_PACKET_TRANSCEIVER_H