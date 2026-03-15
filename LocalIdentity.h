#pragma once

#include "PlatformNet.h"
#include "MACAddress.h"

namespace tcpmsg {

inline bool defineLocalMACAddress(MACAddress& out) {
    uint8_t raw[6] = {0, 0, 0, 0, 0, 0};
    if (!platform::platformDefineLocalMACAddress(raw)) {
        return false;
    }
    out.setBytes(raw);
    return true;
}

} // namespace tcpmsg