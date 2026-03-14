
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

private:
    uint8_t bytes_[6];
};

} // namespace tcpmsg