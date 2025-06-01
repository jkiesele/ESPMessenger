#ifndef SECURE_PACKET_TRANSCEIVER_H
#define SECURE_PACKET_TRANSCEIVER_H

#include <vector>
#include <cstdint>
#include "EncryptionHandler.h"
#include <atomic>
#include <WiFiClient.h>

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

    enum class Status {
        OK,
        SENDING,
        BUSY,
        NO_ACK,
        ERROR
    };
    static String statusToString(Status s) {
        switch (s) {
            case Status::OK:      return "OK";
            case Status::SENDING: return "SENDING";
            case Status::BUSY:    return "BUSY";
            case Status::NO_ACK:  return "NO_ACK";
            case Status::ERROR:   return "ERROR";
            default:             return "UNKNOWN";
        }
    }

    

    bool statusNotError(Status s)const{
        return s == Status::OK || s == Status::SENDING || s == Status::BUSY;
    }

    SecurePacketTransceiver(BackEnd backend = BackEnd::MOCK, 
        const std::vector<uint32_t> * encryptionKeys=0);
    ~SecurePacketTransceiver();

    void setTcpServer(IPAddress ip, uint16_t port) {
        serverIp_   = ip;
        serverPort_ = port;
      }

    void begin();
    Status send(const std::vector<uint8_t>& plainPacket, const std::vector<uint8_t>& destAddress = {});
    bool receive(std::vector<uint8_t>& decryptedPacket);
    bool isSendBusy() const { return sendBusy_; }
    Status getLastStatus() const { return lastStatus_; }
    BackEnd getBackEnd() const;

    // -1 will use the connected wifi channel
    void setFixedChannel(int8_t channel){
        channel_ = channel;
    }

private:
    std::atomic<Status> lastStatus_ { Status::OK };
    EncryptionHandler encryptionHandler_;
    BackEnd backend_;

    static SecurePacketTransceiver* instance_;
    static void onEspNowRecv(const uint8_t* mac, const uint8_t* data, int len);
    void handleEspNowRecv(const uint8_t* data, int len);
    static void onEspNowSend(const uint8_t* mac, esp_now_send_status_t status);
    void handleEspNowSend(const uint8_t* mac, esp_now_send_status_t status);

    // Remove persistent buffer and mutex
    static QueueHandle_t rxQueue_; // Queue of pointers to std::vector<uint8_t>

    std::atomic<bool> sendBusy_;
    int8_t channel_;

    // … in private:
    std::vector<uint8_t>   pendingDest_;
    std::vector<uint8_t>   pendingData_;
    uint8_t                pendingRetries_   = 0;
    const uint8_t          maxRetries_       = 8;  


  WiFiClient     tcpClient_;
  IPAddress      serverIp_;    // set by user
  uint16_t       serverPort_;  // set by user

  int8_t lastChan;

};

#endif // SECURE_PACKET_TRANSCEIVER_H