
#pragma once

#include <stdint.h>
#include <string.h>
#include <vector>

namespace tcpmsg {

class MACAddress {
public:
    MACAddress() {
        memset(bytes_, 0, sizeof(bytes_));
    }

    explicit MACAddress(const uint8_t (&b)[6]) {
        memcpy(bytes_, b, sizeof(bytes_));
    }

    void setBytes(const uint8_t* p) {
        if (p) {
            memcpy(bytes_, p, sizeof(bytes_));
        } else {
            memset(bytes_, 0, sizeof(bytes_));
        }
    }

    const uint8_t* bytes() const { return bytes_; }
    uint8_t* bytes() { return bytes_; }

    bool isZero() const {
        static const uint8_t z[6] = {0, 0, 0, 0, 0, 0};
        return memcmp(bytes_, z, sizeof(bytes_)) == 0;
    }

    bool operator==(const MACAddress& o) const {
        return memcmp(bytes_, o.bytes_, sizeof(bytes_)) == 0;
    }

    bool operator!=(const MACAddress& o) const {
        return !(*this == o);
    }

    static constexpr size_t kStringSize = 18;
    void toCString(char out[kStringSize]) const {
        static const char hex[] = "0123456789ABCDEF";
        for (int i = 0; i < 6; ++i) {
            const uint8_t b = bytes_[i];
            out[i * 3 + 0] = hex[(b >> 4) & 0x0F];
            out[i * 3 + 1] = hex[b & 0x0F];
            if (i < 5) {
                out[i * 3 + 2] = ':';
            }
        }
        out[17] = '\0';
    }

private:
    uint8_t bytes_[6];
};

} // namespace tcpmsg