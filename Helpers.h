
#include <Arduino.h>
#include <stdint.h>
#include <cstring> // memcpy, memcmp
// ------------------------------------------------------------------
// Helper classes
// ------------------------------------------------------------------
class MACAddress {
public:
    MACAddress() : bytes_{0,0,0,0,0,0} {}

    // only accepts a real uint8_t[6] lvalue
    explicit MACAddress(const uint8_t (&b)[6]) { memcpy(bytes_, b, 6); }

    void setBytes(const uint8_t* p) {
        if (p) memcpy(bytes_, p, 6);
    }

    bool isZero() const {
        static const uint8_t z[6] = {0,0,0,0,0,0};
        return memcmp(bytes_, z, 6) == 0;
    }

    const uint8_t* data() const { return bytes_; }

    bool operator==(const MACAddress& o) const { return memcmp(bytes_, o.bytes_, 6) == 0; }
    bool operator!=(const MACAddress& o) const { return !(*this == o); }

private:
    uint8_t bytes_[6];
};


// ------------------------------------------------------------------
// Remote info passed to callbacks
// ------------------------------------------------------------------
struct TCPMsgRemoteInfo {
    IPAddress ip;
    uint16_t  port;
    String    host;   // may be empty
    MACAddress mac;   // sender MAC from envelope (inbound)
    uint16_t  seq = 0;                 // envelope seq (inbound)
};