/* ───────────────  MDNSSniffer.h  ─────────────── */
#pragma once
#include <Arduino.h>
#include <AsyncUDP.h>
#include <vector>

class MDNSSniffer {
public:
    void begin();                                            // call once
    bool resolve(const IPAddress& ip, String& host) const;   // lookup
    void prune(uint32_t maxAgeMs = 10 * 60 * 1000UL);        // optional
    void addByHand(const IPAddress& ip, const String& host);

private:
    void addOrUpdate(const IPAddress& ip, const String& host); //not locked!
    struct Entry {
        IPAddress ip;
        String    host;
        uint32_t  lastSeen;
    };

    void handlePacket(AsyncUDPPacket& pkt);
    static String parseHost(const uint8_t* d, size_t len, const IPAddress& remoteip);

    AsyncUDP           udp_;
    SemaphoreHandle_t  mtx_ = nullptr;
    std::vector<Entry> cache_;
};