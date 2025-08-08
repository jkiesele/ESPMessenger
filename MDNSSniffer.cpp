/* ───────────────  MDNSSniffer.cpp  ─────────────── */
#include "MDNSSniffer.h"
#include "LoggingBase.h"

void MDNSSniffer::begin()
{
    mtx_ = xSemaphoreCreateMutex();

    udp_.listenMulticast(IPAddress(224,0,0,251), 5353);
    udp_.onPacket([this](AsyncUDPPacket& pkt) { handlePacket(pkt); });
}

void MDNSSniffer::handlePacket(AsyncUDPPacket& pkt)
{
    String host = parseHost(pkt.data(), pkt.length(), pkt.remoteIP());
    if (host.isEmpty()) return;

    if (xSemaphoreTake(mtx_, 0)) {
        // update or add entry
        addOrUpdate(pkt.remoteIP(), host);
        xSemaphoreGive(mtx_);
        gLogger->println("MDNSSniffer: New host " + host + " at " + pkt.remoteIP().toString());
    }
}

// ─── inside MDNSSniffer.cpp ────────────────────────────────────────
namespace {

bool readName(const uint8_t* msg, size_t len, size_t& off, char* out, size_t outSz)
{
    size_t pos = 0;
    size_t jumps = 0;            // loop-guard for bogus packets

    while (off < len && jumps < 10) {
        uint8_t labLen = msg[off];

        // pointer?
        if ((labLen & 0xC0) == 0xC0) {
            if (off + 1 >= len) return false;
            uint16_t ptr = ((labLen & 0x3F) << 8) | msg[off + 1];
            off += 2;
            off = (size_t)-1;    // signal: caller must NOT advance past name
            off = ptr;
            ++jumps;
            continue;
        }

        // end of name
        if (labLen == 0) { ++off; break; }
        if (labLen > 63 || off + 1 + labLen > len) return false;
        if (pos + labLen + 1 >= outSz) return false;      // overflow

        ++off;
        memcpy(out + pos, msg + off, labLen);
        pos += labLen;
        out[pos++] = '.';
        off += labLen;
    }

    if (pos == 0) return false;
    out[pos - 1] = '\0';          // strip trailing dot
    return true;
}

String parseHostFull(const uint8_t* msg, size_t len, IPAddress senderIP)
{
    if (len < 12) return {};

    uint16_t qd = (msg[4] << 8) | msg[5];
    uint16_t an = (msg[6] << 8) | msg[7];
    size_t   off = 12;

    /* ---- skip question section ---- */
    char tmp[256];
    for (uint16_t i = 0; i < qd; ++i) {
        if (!readName(msg, len, off, tmp, sizeof(tmp))) return {};
        if (off == (size_t)-1) return {};      // malformed
        if (off + 4 > len) return {};
        off += 4;                              // QTYPE + QCLASS
    }

    /* ---- walk answer section ---- */
    for (uint16_t i = 0; i < an; ++i) {
        size_t nameOff = off;                  // save for later
        if (!readName(msg, len, off, tmp, sizeof(tmp))) return {};
        if (off == (size_t)-1) {               // compressed name already read
            /* nothing */
        }
        if (off + 10 > len) return {};
        uint16_t type  = (msg[off] << 8) | msg[off+1];
        uint16_t _class= (msg[off+2] << 8) | msg[off+3];
        uint16_t rdlen = (msg[off+8] << 8) | msg[off+9];
        off += 10;
        if (off + rdlen > len) return {};

        if (type == 0x0001 && _class == 0x0001 && rdlen == 4) { // A record
            IPAddress rdata(msg[off], msg[off+1], msg[off+2], msg[off+3]);
            if (rdata == senderIP) {
                /* rewind to extract host name again (non-compressed) */
                size_t tmpOff = nameOff;
                if (readName(msg, len, tmpOff, tmp, sizeof(tmp)))
                    return String(tmp);
            }
        }
        off += rdlen;
    }
    return {};
}

} // namespace

/* ─── replace your old function with this version ───────── */
String MDNSSniffer::parseHost(const uint8_t* d, size_t len, const IPAddress& remoteip)
{
    return parseHostFull(d, len, remoteip);   // pass sender IP
}

bool MDNSSniffer::resolve(const IPAddress& ip, String& host) const
{
    bool ok = false;
    if (xSemaphoreTake(mtx_, pdMS_TO_TICKS(10))) {
        for (const auto& e : cache_) {
            if (e.ip == ip) { host = e.host; ok = true; break; }
        }
        xSemaphoreGive(mtx_);
    }
    return ok;
}

void MDNSSniffer::prune(uint32_t maxAgeMs)
{
    uint32_t now = millis();
    if (xSemaphoreTake(mtx_, pdMS_TO_TICKS(10))) {
        cache_.erase(
            std::remove_if(cache_.begin(), cache_.end(),
                [&](const Entry& e){ return now - e.lastSeen > maxAgeMs; }),
            cache_.end());
        xSemaphoreGive(mtx_);
    }
}
//not locked!
void MDNSSniffer::addOrUpdate(const IPAddress& ip, const String& host)
{
    auto it = std::find_if(cache_.begin(), cache_.end(),
        [&](const Entry& e){ return e.ip == ip; });
    if (it != cache_.end()) {
        it->host = host;
        it->lastSeen = millis();
    } else {
        cache_.emplace_back(Entry{ip, host, millis()});
    }
}

void MDNSSniffer::addByHand(const IPAddress& ip, const String& host)
{
    if (xSemaphoreTake(mtx_, pdMS_TO_TICKS(10))) {
        addOrUpdate(ip, host);
        xSemaphoreGive(mtx_);
    }
}
