
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