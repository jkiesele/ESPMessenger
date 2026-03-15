
#pragma once

#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))

#include <cstdint>
#include <arpa/inet.h>

class IPAddress {
public:
    IPAddress() = default;

    IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        bytes_[0] = a;
        bytes_[1] = b;
        bytes_[2] = c;
        bytes_[3] = d;
    }

    explicit IPAddress(uint32_t hostOrder) {
        bytes_[0] = static_cast<uint8_t>((hostOrder >> 24) & 0xFF);
        bytes_[1] = static_cast<uint8_t>((hostOrder >> 16) & 0xFF);
        bytes_[2] = static_cast<uint8_t>((hostOrder >> 8)  & 0xFF);
        bytes_[3] = static_cast<uint8_t>( hostOrder        & 0xFF);
    }

    uint8_t operator[](int i) const { return bytes_[i]; }

    uint32_t toNetworkOrder() const {
        const uint32_t host =
            (static_cast<uint32_t>(bytes_[0]) << 24) |
            (static_cast<uint32_t>(bytes_[1]) << 16) |
            (static_cast<uint32_t>(bytes_[2]) << 8)  |
            (static_cast<uint32_t>(bytes_[3]));
        return htonl(host);
    }

    //cast operator to uint32_t in network byte order, same signature as Arduino's IPAddress::operator uint32_t()
    explicit operator uint32_t() const { return toNetworkOrder(); }

private:
    uint8_t bytes_[4] = {0, 0, 0, 0};
};

//for SocketUtils / SocketServer

#include <cstddef>
#include <cstdint>
#include <cerrno>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#else
// ESP32 ------------ /////// 

#include <Arduino.h>
#include <WiFi.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <errno.h>

#endif



// ---- helpers for MAC address resolving/defining as a unique ID, not strictly coupled to the right hardware!

#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))
#include <cstdint>
#include <arpa/inet.h>
#include <cstddef>
#include <cerrno>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include <ifaddrs.h>
#include <net/if.h>

#if defined(__linux__)
#include <netpacket/packet.h>
#elif defined(__APPLE__) && defined(__MACH__)
#include <net/if_dl.h>
#endif

#else
// ESP32 ------------ ///////

#include <Arduino.h>
#include <WiFi.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <errno.h>

#endif

namespace tcpmsg {
    namespace platform{

inline bool platformDefineLocalMACAddress(uint8_t out[6]) {
    if (!out) {
        return false;
    }

#if defined(ARDUINO_ARCH_ESP32)
    uint8_t raw[6] = {0, 0, 0, 0, 0, 0};
    WiFi.macAddress(raw);

    bool allZero = true;
    for (int i = 0; i < 6; ++i) {
        out[i] = raw[i];
        if (raw[i] != 0) {
            allZero = false;
        }
    }
    return !allZero;

#elif defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0 || !ifaddr) {
        return false;
    }

    bool found = false;

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_name) {
            continue;
        }

        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }

#if defined(__linux__)
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            const struct sockaddr_ll* s =
                reinterpret_cast<const struct sockaddr_ll*>(ifa->ifa_addr);

            if (s->sll_halen != 6) {
                continue;
            }

            bool allZero = true;
            for (int i = 0; i < 6; ++i) {
                out[i] = static_cast<uint8_t>(s->sll_addr[i]);
                if (out[i] != 0) {
                    allZero = false;
                }
            }

            if (!allZero) {
                found = true;
                break;
            }
        }

#elif defined(__APPLE__) && defined(__MACH__)
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            const struct sockaddr_dl* s =
                reinterpret_cast<const struct sockaddr_dl*>(ifa->ifa_addr);

            if (s->sdl_alen != 6) {
                continue;
            }

            const uint8_t* mac =
                reinterpret_cast<const uint8_t*>(LLADDR(s));

            bool allZero = true;
            for (int i = 0; i < 6; ++i) {
                out[i] = mac[i];
                if (out[i] != 0) {
                    allZero = false;
                }
            }

            if (!allZero) {
                found = true;
                break;
            }
        }
#endif
    }

    freeifaddrs(ifaddr);
    return found;

#else
    (void)out;
    return false;
#endif
}

    } // namespace platform
} // namespace tcpmsg