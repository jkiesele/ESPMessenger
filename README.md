
# ESPMessenger

A lightweight messaging library for ESP microcontrollers.

## Features

- Simple message passing
- Efficient memory usage
- Easy integration with PlatformIO

## Installation

Add to your `platformio.ini`:

```ini
lib_deps = ESPMessenger
```

## Usage

```cpp
// Demo sketch for the updated TCPMessenger API (MACAddress, ACKs, RX worker, etc.)
// Assumptions:
// - You have TCPMessenger.{h,cpp} in the project (as you posted).
// - SharedDataFormats::ReservoirInfo exists and implements Serializable
//   (typeId(), payloadSize(), serializeTo()) and provides fromBuffer() or equivalent.
// - You have WiFi credentials and the peer device's MAC available.

#include <Arduino.h>
#include <WiFi.h>

#include "TCPMessenger.h"
#include "EncryptionHandler.h"

// Your project header that defines ReservoirInfo
#include "SharedDataFormats.h"

using SharedDataFormats::ReservoirInfo;

// -----------------------------------------------------------------------------
// WiFi config (fill in)
// -----------------------------------------------------------------------------
static const char* WIFI_SSID = "YOUR_SSID";
static const char* WIFI_PASS = "YOUR_PASS";

// -----------------------------------------------------------------------------
// Peer config (fill in)
// - host: mDNS hostname of the peer (without ".local" if your resolver strips it; your code supports both)
// - mac : peer MAC (used for envelope dstMac check on the receiver)
// -----------------------------------------------------------------------------
static const char* PEER_HOST = "hydro-node-b.local";   // example
static const uint8_t PEER_MAC_BYTES[6] = { 0x24, 0x6F, 0x28, 0xAA, 0xBB, 0xCC }; // example

// Channel choice (0..255). Keep it simple here.
static constexpr uint8_t CHAN = 0;

// -----------------------------------------------------------------------------
// Global objects
// -----------------------------------------------------------------------------
static EncryptionHandler gEnc;           // configure keys in your EncryptionHandler as usual
static TCPMessenger      gMsg(&gEnc);    // pass enc pointer, or nullptr for plaintext

// Last time we sent
static uint32_t gLastSendMs = 0;

// -----------------------------------------------------------------------------
// Helper: connect WiFi
// -----------------------------------------------------------------------------
static void connectWiFi()
{
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.print("WiFi connecting");
  while (WiFi.status() != WL_CONNECTED) {
    delay(250);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("WiFi OK, IP=");
  Serial.println(WiFi.localIP());
}

// -----------------------------------------------------------------------------
// Callback: incoming frame -> interpret as ReservoirInfo
// -----------------------------------------------------------------------------
static void onReceiveCB(const TCPMsgRemoteInfo& from,
                        uint8_t type,
                        uint8_t chan,
                        const uint8_t* payload,
                        uint16_t len)
{
  // This callback runs in your RX worker task context (not in the AsyncTCP ISR-ish context).
  // Keep it reasonably fast; avoid heavy blocking.

  // Filter on type if you want strictness
  if (type != ReservoirInfo::TYPE_ID) {
    Serial.printf("[RX] Ignored type=0x%02X chan=%u len=%u\n", type, chan, len);
    return;
  }

  ReservoirInfo info;
  // Adjust to your actual API:
  // - many of your Serializable-like formats have something like fromBuffer(ptr,len)->bool
  // - if it returns void, remove the check
  const bool ok = info.fromBuffer(payload, len);
  if (!ok) {
    Serial.printf("[RX] ReservoirInfo decode failed (len=%u)\n", len);
    return;
  }

  Serial.printf("[RX] ReservoirInfo from %s (host='%s') seq=%u chan=%u\n",
                from.ip.toString().c_str(),
                from.host.c_str(),
                from.seq,
                chan);

  // Print a few fields (replace with real field names)
  // Example placeholders:
  Serial.printf("     level_mm=%d  ec_mS=%0.3f  temp_C=%0.2f\n",
                (int)info.level_mm,
                (double)info.ec_mS,
                (double)info.temp_C);
}

// -----------------------------------------------------------------------------
// Callback: send completion (ACK interpreted by TCPMessenger)
// -----------------------------------------------------------------------------
static void onSendDoneCB(TCPMsgResult rc,
                         const TCPMsgRemoteInfo& to,
                         uint8_t type,
                         uint8_t chan,
                         uint16_t lenPlain)
{
  Serial.printf("[TX done] rc=%u type=0x%02X chan=%u plainLen=%u to=%s host='%s' seq=%u flags=0x%02X\n",
                (unsigned)rc,
                (unsigned)type,
                (unsigned)chan,
                (unsigned)lenPlain,
                to.ip.toString().c_str(),
                to.host.c_str(),
                (unsigned)gMsg.lastSendSeq(),
                (unsigned)gMsg.lastSendFlags());

  // If you care about who ACKed you (MAC in ACK payload)
  const MACAddress& ackMac = gMsg.lastAckMac();
  Serial.printf("          ackMac=%02X:%02X:%02X:%02X:%02X:%02X\n",
                ackMac.data()[0], ackMac.data()[1], ackMac.data()[2],
                ackMac.data()[3], ackMac.data()[4], ackMac.data()[5]);
}

// -----------------------------------------------------------------------------
// Arduino setup / loop
// -----------------------------------------------------------------------------
void setup()
{
  Serial.begin(115200);
  delay(200);

  connectWiFi();

  // Start messenger (caches local MAC, starts mDNS sniffer helper, starts TCP server)
  gMsg.begin();

  // Register callbacks
  gMsg.onReceive(onReceiveCB);
  gMsg.onSendDone(onSendDoneCB);

  Serial.printf("TCPMessenger server active=%d port=%u\n",
                (int)gMsg.serverActive(), (unsigned)gMsg.serverPort());
}

void loop()
{
  // Messenger itself is async; loop() can be empty. Keeping it explicit:
  gMsg.loop();

  // Send a ReservoirInfo once per second as a demo
  const uint32_t now = millis();
  if (now - gLastSendMs >= 1000) {
    gLastSendMs = now;

    // Prepare payload
    ReservoirInfo info;
    // Fill fields (replace with your actual names)
    info.level_mm = 123;
    info.ec_mS    = 1.234f;
    info.temp_C   = 22.5f;

    // Expected destination MAC is REQUIRED and must be non-zero
    MACAddress peerMac(PEER_MAC_BYTES);

    // Send via mDNS hostname (will resolve in worker thread)
    TCPMsgResult rc = gMsg.sendToHost(info, CHAN, PEER_HOST, peerMac);

    Serial.printf("[TX] queued rc=%u busy=%d\n", (unsigned)rc, (int)gMsg.isBusy());
    // rc is typically TCPMSG_QUEUED (success path) or an error (busy/too_large/resolve etc.)
  }

  delay(5);
}

```

## Documentation

See the examples folder for more use cases.
