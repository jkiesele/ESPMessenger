/*  ────────────────────────────────────────────────────────────────
    MDNSSniffer.cpp
    ──────────────────────────────────────────────────────────────── */
#include "MDNSSniffer.h"
#include <lwip/inet.h>

void MDNSSniffer::begin()
{
    mtx_ = xSemaphoreCreateMutex();
    q_   = xQueueCreate(8, sizeof(AsyncUDPPacket*));     // small queue

    // Task takes ownership of queued packet pointers and deletes them
    xTaskCreatePinnedToCore(taskEntry, "mdnsSniff", 4096, this, 2, nullptr, 0);

    // ── open multicast socket (non-blocking) ─────────────────────
    udp_.listenMulticast(IPAddress(224,0,0,251), 5353);
    udp_.onPacket([this](AsyncUDPPacket& p) {
        // copy packet into heap so we can enqueue a pointer
        auto* copy = new AsyncUDPPacket(p);              // ← light copy ctor
        if (xQueueSendToBack(q_, &copy, 0) != pdTRUE)    // queue full → drop
            delete copy;
    });
}

void MDNSSniffer::taskEntry(void* arg)
{
    static_cast<MDNSSniffer*>(arg)->taskLoop();
}

void MDNSSniffer::taskLoop()
{
    for (;;)
    {
        AsyncUDPPacket* pktPtr = nullptr;
        if (xQueueReceive(q_, &pktPtr, portMAX_DELAY) != pdTRUE) continue;

        handlePacket(*pktPtr);
        delete pktPtr;                // release heap copy
    }
}

void MDNSSniffer::handlePacket(AsyncUDPPacket& pkt)
{
    String host = parseHostFromMDNS(pkt.data(), pkt.length());
    if (host.isEmpty()) return;

    if (xSemaphoreTake(mtx_, portMAX_DELAY))
    {
        // update or insert
        for (auto& e : cache_) {
            if (e.ip == pkt.remoteIP()) {
                e.host     = host;
                e.lastSeen = millis();
                xSemaphoreGive(mtx_);
                return;
            }
        }
        cache_.push_back({pkt.remoteIP(), host, millis()});
        xSemaphoreGive(mtx_);
    }
}

String MDNSSniffer::parseHostFromMDNS(const uint8_t* d, size_t len)
{
    /* Minimal, fast scan: look for label length byte + “local” literal,
       then read preceding label. Works for typical “myESP.local” replies. */
    for (size_t i = 0; i + 6 < len; ++i) {
        if (memcmp(d + i, "\x05local", 6) == 0 && i > 1 && d[i-1] < 64) {
            uint8_t labLen = d[i-1];
            if (labLen > 0 && labLen < 64 && i >= labLen + 1) {
                return String(reinterpret_cast<const char*>(d + i - labLen), labLen);
            }
        }
    }
    return {};
}

bool MDNSSniffer::resolve(const IPAddress& ip, String& host) const
{
    if (!mtx_) return false;
    bool found = false;
    if (xSemaphoreTake(mtx_, pdMS_TO_TICKS(10))) {
        for (const auto& e : cache_) {
            if (e.ip == ip) { host = e.host; found = true; break; }
        }
        xSemaphoreGive(mtx_);
    }
    return found;
}

void MDNSSniffer::prune(uint32_t maxAgeMs)
{
    if (!mtx_) return;
    uint32_t now = millis();
    if (xSemaphoreTake(mtx_, pdMS_TO_TICKS(10))) {
        cache_.erase(
            std::remove_if(cache_.begin(), cache_.end(),
                [&](const Entry& e){ return (now - e.lastSeen) > maxAgeMs; }),
            cache_.end());
        xSemaphoreGive(mtx_);
    }
}