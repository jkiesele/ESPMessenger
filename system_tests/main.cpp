#include <WiFi.h>

#include "TCPMessenger.h"
#include "EncryptionHandler.h"
#include "DataFormats.h"
#include "passwords.h"

using tcpmsg::TCPMessenger;
using tcpmsg::MACAddress;
using tcpmsg::formats::TextMessage;

namespace {

const char* kSsid = secret::ssid;
const char* kPass = secret::password;

const IPAddress kRemoteIp(192, 168, 178, 22);
constexpr uint16_t kLocalPort  = 25001;
constexpr uint16_t kRemotePort = 25001;
constexpr uint8_t  kChanId     = 1;

MACAddress makeMac(uint8_t a0, uint8_t a1, uint8_t a2,
                   uint8_t a3, uint8_t a4, uint8_t a5) {
    const uint8_t raw[6] = {a0, a1, a2, a3, a4, a5};
    return MACAddress(raw);
}

const MACAddress kLocalMac  = makeMac(0x10, 0x20, 0x30, 0x40, 0x50, 0x02);
const MACAddress kRemoteMac = makeMac(0x10, 0x20, 0x30, 0x40, 0x50, 0x01);

// Replace with your actual shared keys.
const std::vector<uint32_t> kKeys = {
    0x12345678u,
    0xCAFEBABEu
};

tcpmsg::EncryptionHandler gEnc(&kKeys);
TCPMessenger gMessenger;

String gLine;

void printByteString(const tcpmsg::ByteString& s) {
    const uint8_t* p = s.data();
    const uint16_t n = s.size();
    if (!p || n == 0) {
        return;
    }
    Serial.write(p, n);
}

void connectWifi() {
    WiFi.mode(WIFI_STA);
    WiFi.begin(kSsid, kPass);

    while (WiFi.status() != WL_CONNECTED) {
        delay(300);
        Serial.print(".");
    }
    Serial.println();
    Serial.print("WiFi connected, IP=");
    Serial.println(WiFi.localIP());
}

void processSerialInput() {
    while (Serial.available() > 0) {
        const char c = static_cast<char>(Serial.read());

        if (c == '\r') {
            continue;
        }

        if (c == '\n') {
            if (gLine.length() > 0) {
                TextMessage msg;
                msg.setText(gLine.c_str());

                TCPMessenger::SendOptions opt;
                opt.timeoutMs = 500;
                opt.maxRetries = 3;
                opt.retryDelayMs = 100;

                const auto rc =
                    gMessenger.sendToIP(msg, kChanId, kRemoteIp, kRemotePort, kRemoteMac, opt);

                if (rc != TCPMessenger::Result::Ok) {
                    Serial.print("[send queue failed] rc=");
                    Serial.println(static_cast<int>(rc));
                }

                gLine = "";
            }
        } else {
            gLine += c;
        }
    }
}

void processMessenger() {
    TCPMessenger::SendResult sr;
    if (gMessenger.popSendResult(sr)) {
        Serial.print("[send result] rc=");
        Serial.println(static_cast<int>(sr.rc));
    }

    TCPMessenger::ReceivedMessage rx;
    TCPMessenger::Result rc = TCPMessenger::Result::NoMessage;
    if (gMessenger.popReceivedMessage(rx, rc)) {
        if (rx.type == TextMessage::TYPE_ID) {
            TextMessage msg;
            if (msg.fromBuffer(rx.payload.data(), static_cast<uint16_t>(rx.payload.size()))) {
                Serial.print("[rx] ");
                printByteString(msg.text());
                Serial.println();
            } else {
                Serial.println("[rx] TextMessage decode failed");
            }
        } else {
            Serial.print("[rx] unexpected type=");
            Serial.println(static_cast<int>(rx.type));
        }
    } else if (rc != TCPMessenger::Result::NoMessage) {
        Serial.print("[rx error] rc=");
        Serial.println(static_cast<int>(rc));
    }
}

} // namespace

void setup() {
    Serial.begin(115200);
    delay(500);

    connectWifi();

    if (!gMessenger.begin(kLocalPort, kLocalMac, &gEnc)) {
        Serial.println("gMessenger.begin failed");
        while (true) {
            delay(1000);
        }
    }

    Serial.println("ESP32 text terminal ready.");
}

void loop() {
    processSerialInput();
    processMessenger();
    delay(10);
}