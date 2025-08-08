/*  ────────────────────────────────────────────────────────────────
    MDNSSniffer.h
    Put this in your include folder, then:
        #include "MDNSSniffer.h"
    ──────────────────────────────────────────────────────────────── */
#pragma once
#include <Arduino.h>
#include <AsyncUDP.h>
#include <vector>

class MDNSSniffer {
public:
    MDNSSniffer() = default;

    /** Start background task + UDP socket. Call once from setup()/begin(). */
    void begin();

    /** Return true and fill |host| if we already know a name for |ip|.       */
    bool resolve(const IPAddress& ip, String& host) const;

    /** Optionally prune entries older than |ms| (call from loop).           */
    void prune(uint32_t maxAgeMs = 10 * 60 * 1000UL);   // default 10 min

private:
    struct Entry {
        IPAddress  ip;
        String     host;
        uint32_t   lastSeen;  // millis()
    };

    // FreeRTOS objects
    static void      taskEntry(void* arg);
    void             taskLoop();
    QueueHandle_t    q_   = nullptr;
    SemaphoreHandle_t mtx_ = nullptr;

    // UDP
    AsyncUDP udp_;

    // State
    std::vector<Entry> cache_;

    // Helpers
    void handlePacket(AsyncUDPPacket& pkt);
    static String  parseHostFromMDNS(const uint8_t* data, size_t len);
};