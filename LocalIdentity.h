#pragma once

#include "PlatformNet.h"
#include "MACAddress.h"

namespace tcpmsg {

/*
 * Defines the local MAC address for the platform.
 * - On Linux/Mac, this tries to find a non-zero MAC address from the system's
 *   network interfaces, skipping loopback and zero addresses.
 * - On ESP32, this uses WiFi.macAddress() to get the device's MAC address.
 *   Here, make sure WiFi is turned on (e.g. WiFi.mode(WIFI_STA)) before calling this function.
 */
inline bool defineLocalMACAddress(MACAddress& out) {
    uint8_t raw[6] = {0, 0, 0, 0, 0, 0};
    if (!platform::platformDefineLocalMACAddress(raw)) {
        return false;
    }
    out.setBytes(raw);
    return true;
}

} // namespace tcpmsg