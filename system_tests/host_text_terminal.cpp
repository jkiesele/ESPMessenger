// c++ -std=c++17 -Wall -Wextra -pedantic -pthread SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp  InboundConnection.cpp OutboundTransaction.cpp PlatformThreads.cpp  PlatformMutex.cpp TCPTransport.cpp MessengerCodec.cpp TCPMessenger.cpp  EncryptionHandler.cpp host_text_terminal.cpp  -o host_text_terminal

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "TCPMessenger.h"
#include "EncryptionHandler.h"
#include "DataFormats.h"

using tcpmsg::TCPMessenger;
using tcpmsg::MACAddress;
using tcpmsg::formats::TextMessage;

namespace {

const IPAddress kRemoteIp(192, 168, 178, 35);
constexpr uint16_t kLocalPort  = 25001;
constexpr uint16_t kRemotePort = 25001;
constexpr uint8_t  kChanId     = 1;

MACAddress makeMac(uint8_t a0, uint8_t a1, uint8_t a2,
                   uint8_t a3, uint8_t a4, uint8_t a5) {
    const uint8_t raw[6] = {a0, a1, a2, a3, a4, a5};
    return MACAddress(raw);
}

const MACAddress kLocalMac  = makeMac(0x10, 0x20, 0x30, 0x40, 0x50, 0x01);
const MACAddress kRemoteMac = makeMac(0x10, 0x20, 0x30, 0x40, 0x50, 0x02);

// Replace with your actual shared keys.
const std::vector<uint32_t> kKeys = {
    0x12345678u,
    0xCAFEBABEu
};

std::atomic<bool> gRunning{true};

void printByteString(const tcpmsg::ByteString& s) {
    const uint8_t* p = s.data();
    const uint16_t n = s.size();
    for (uint16_t i = 0; i < n; ++i) {
        std::cout << static_cast<char>(p[i]);
    }
}

void stdinThread(TCPMessenger* messenger) {
    while (gRunning.load()) {
        std::string line;
        if (!std::getline(std::cin, line)) {
            gRunning.store(false);
            break;
        }

        if (line == "/quit" || line == "/exit") {
            gRunning.store(false);
            break;
        }

        TextMessage msg;
        msg.setText(line.c_str());

        TCPMessenger::SendOptions opt;
        opt.timeoutMs = 500;
        opt.maxRetries = 3;
        opt.retryDelayMs = 100;

        const auto rc = messenger->sendToIP(msg, kChanId, kRemoteIp, kRemotePort, kRemoteMac, opt);
        if (rc != TCPMessenger::Result::Ok) {
            std::cout << "[send queue failed] rc=" << static_cast<int>(rc) << "\n";
        }
    }
}

} // namespace

int main() {
    tcpmsg::EncryptionHandler enc(&kKeys);
    TCPMessenger messenger;

    if (!messenger.begin(kLocalPort, kLocalMac, &enc)) {
        std::cerr << "messenger.begin failed\n";
        return 1;
    }

    std::cout << "Text terminal running. Type lines and press enter.\n";
    std::cout << "Use /quit to exit.\n";

    std::thread inThread(stdinThread, &messenger);

    while (gRunning.load()) {
        TCPMessenger::SendResult sr;
        if (messenger.popSendResult(sr)) {
            std::cout << "[send result] rc=" << static_cast<int>(sr.rc)
                      << " ip=" << static_cast<int>(sr.ip[0]) << "."
                      << static_cast<int>(sr.ip[1]) << "."
                      << static_cast<int>(sr.ip[2]) << "."
                      << static_cast<int>(sr.ip[3])
                      << " port=" << sr.port << "\n";
        }

        TCPMessenger::ReceivedMessage rx;
        TCPMessenger::Result rc = TCPMessenger::Result::NoMessage;
        if (messenger.popReceivedMessage(rx, rc)) {
            if (rx.type == TextMessage::TYPE_ID) {
                TextMessage msg;
                if (msg.fromBuffer(rx.payload.data(), static_cast<uint16_t>(rx.payload.size()))) {
                    std::cout << "[rx] ";
                    printByteString(msg.text());
                    std::cout << "\n";
                } else {
                    std::cout << "[rx] TextMessage decode failed\n";
                }
            } else {
                std::cout << "[rx] unexpected type=" << static_cast<int>(rx.type) << "\n";
            }
        } else if (rc != TCPMessenger::Result::NoMessage) {
            std::cout << "[rx error] rc=" << static_cast<int>(rc) << "\n";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    messenger.end();
    if (inThread.joinable()) {
        inThread.join();
    }

    return 0;
}