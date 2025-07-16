#ifndef TCP_MESSENGER_H
#define TCP_MESSENGER_H

#include <Arduino.h>
#include <stdint.h>
#include <functional>
#include <vector>

#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPmDNS.h>

#include "Serializable.h"
#include "EncryptionHandler.h"   

// ------------------------------------------------------------------
// Config
// ------------------------------------------------------------------
#ifndef TCPMSG_MAX_PAYLOAD_ENCRYPTED
#define TCPMSG_MAX_PAYLOAD_ENCRYPTED 255  // constrained by 1-byte length field
#endif

// ------------------------------------------------------------------
// Result codes
// ------------------------------------------------------------------
enum TCPMsgResult : uint8_t {
    TCPMSG_OK = 0,
    TCPMSG_ERR_NOT_CONNECTED,
    TCPMSG_ERR_RESOLVE,
    TCPMSG_ERR_TOO_LARGE,
    TCPMSG_ERR_ENCRYPT,
    TCPMSG_ERR_WRITE,
    TCPMSG_ERR_TRANSPORT,
    TCPMSG_ERR_DECODE,
};

// ------------------------------------------------------------------
// Connection / source info provided to receive callback
// ------------------------------------------------------------------
struct TCPMsgRemoteInfo {
    IPAddress ip;
    uint16_t  port;
    String    host;   // may be empty if unknown
};

// ------------------------------------------------------------------
// Callback type aliases
// ------------------------------------------------------------------
using TCPMsgReceiveCB =
    std::function<void(const TCPMsgRemoteInfo& from,
                       uint8_t type,
                       const uint8_t* payload,
                       uint8_t len)>;

using TCPMsgSendDoneCB =
    std::function<void(TCPMsgResult rc,
                       const TCPMsgRemoteInfo& to,
                       uint8_t type,
                       uint8_t len)>;


// ------------------------------------------------------------------
// TCPMessenger
//   - One global singleton instance (see _tcpMessengerSingleton).
//   - AsyncTCP server for inbound.
//   - One-shot AsyncTCP client connect for outbound sends.
//   - Wire format: [type:1][encLen:1][encPayload:encLen].
//   - If EncryptionHandler present: encPayload = plaintext + CRC + XOR.
//   - If no encryption: encPayload = plaintext.
// ------------------------------------------------------------------
class TCPMessenger {
public:
    explicit TCPMessenger(EncryptionHandler* enc = nullptr);
    ~TCPMessenger();

    TCPMessenger(const TCPMessenger&) = delete;
    TCPMessenger& operator=(const TCPMessenger&) = delete;

    // ------------------------------------------------------------------
    // Server side
    // ------------------------------------------------------------------
    bool beginServer(uint16_t port);
    void endServer();
    bool serverActive() const { return (server_ != nullptr); }
    uint16_t serverPort() const { return serverPort_; }

    // ------------------------------------------------------------------
    // Send API (one-shot client connection)
    // ------------------------------------------------------------------
    TCPMsgResult sendToIP(const IPAddress& ip,
                          uint16_t port,
                          const Serializable& msg);

    TCPMsgResult sendToHost(const char* host,
                            uint16_t port,
                            const Serializable& msg);

    TCPMsgResult sendToHost(const String& host,
                            uint16_t port,
                            const Serializable& msg) {
        return sendToHost(host.c_str(), port, msg);
    }

    // ------------------------------------------------------------------
    // Callback registration
    // ------------------------------------------------------------------
    void onReceive(TCPMsgReceiveCB cb) { recvCB_ = cb; }
    void onSendDone(TCPMsgSendDoneCB cb) { sendDoneCB_ = cb; }

    // ------------------------------------------------------------------
    // Manual loop (no-op in AsyncTCP mode; kept for symmetry)
    // ------------------------------------------------------------------
    void loop();

private:
    // -------- Internal per-client receive context --------------------
    struct ClientCtx {
        AsyncClient* client;
        TCPMsgRemoteInfo remote;
        bool haveHeader;
        uint8_t rxType;
        uint8_t rxLenEnc;
        uint8_t rxPos;
        uint8_t rxBuf[TCPMSG_MAX_PAYLOAD_ENCRYPTED];

        ClientCtx(AsyncClient* c)
        : client(c), haveHeader(false), rxType(0), rxLenEnc(0), rxPos(0) {}
    };

    // linked list of active clients
    struct ClientNode {
        ClientCtx* ctx;
        ClientNode* next;
    };

    ClientCtx* addCtx(AsyncClient* c, const IPAddress& ip, uint16_t port);
    void       removeCtx(AsyncClient* c);

    // AsyncServer onClient handler
    void handleNewClient(AsyncClient* client);

    // AsyncClient event handlers for server-accepted clients (static fwd)
    static void _onClientData(void* arg, AsyncClient* c, void* data, size_t len);
    static void _onClientDisconnect(void* arg, AsyncClient* c);
    static void _onClientError(void* arg, AsyncClient* c, int8_t error);
    static void _onClientTimeout(void* arg, AsyncClient* c, uint32_t time);
    static void _onClientPoll(void* arg, AsyncClient* c);

    // Instance handlers
    void onClientData(ClientCtx* ctx, const uint8_t* data, size_t len);
    void onClientDisconnect(ClientCtx* ctx);
    void onClientError(ClientCtx* ctx, int8_t error);
    void onClientTimeout(ClientCtx* ctx, uint32_t time);
    void onClientPoll(ClientCtx* ctx);

    // Frame parsing for a given context
    void parseBytes(ClientCtx* ctx, const uint8_t* data, size_t len);
    void dispatchFrame(const TCPMsgRemoteInfo& from,
                       uint8_t type,
                       const uint8_t* encPayload,
                       uint8_t encLen);

    // Build plaintext payload from Serializable
    TCPMsgResult buildPlain(const Serializable& msg,
                            std::vector<uint8_t>& outPlain,
                            uint8_t& outType);

    // Encrypt payload (or pass-through)
    TCPMsgResult encryptPayload(std::vector<uint8_t>& buf);

    // Resolve hostname (mDNS .local first, then DNS)
    bool resolveHost(const char* host, IPAddress& outIP);

    // Low-level send using a one-shot AsyncClient
    TCPMsgResult sendFrame(const TCPMsgRemoteInfo& to,
                           uint8_t type,
                           const uint8_t* encPayload,
                           uint8_t encLen);

    // AsyncClient events for one-shot outbound sends (static fwd)
    struct OutboundCtx {
        AsyncClient* client;
        TCPMsgRemoteInfo to;
        uint8_t type;
        uint8_t encLen;            // encrypted length
        std::vector<uint8_t> frame; // header + encPayload
        TCPMessenger* self;

        OutboundCtx() : client(nullptr), type(0), encLen(0), self(nullptr) {}
    };

    static void _onOutboundConnect(void* arg, AsyncClient* c);
    static void _onOutboundError(void* arg, AsyncClient* c, int8_t error);
    static void _onOutboundDisconnect(void* arg, AsyncClient* c);

    // Outbound instance handlers
    void onOutboundConnect(OutboundCtx* ctx, AsyncClient* c);
    void onOutboundError(OutboundCtx* ctx, AsyncClient* c, int8_t error);
    void onOutboundDisconnect(OutboundCtx* ctx, AsyncClient* c);

    void notifySendDone(TCPMsgResult rc,
                        const TCPMsgRemoteInfo& to,
                        uint8_t type,
                        uint8_t plainLen);  // deliver *plaintext* len to user

private:
    EncryptionHandler* enc_;
    AsyncServer*       server_;
    uint16_t           serverPort_;

    ClientNode* head_;   // linked list of connected server clients

    TCPMsgReceiveCB  recvCB_;
    TCPMsgSendDoneCB sendDoneCB_;
};

// ------------------------------------------------------------------
// Global singleton pointer (defined in TCPMessenger.cpp).
// Only the first constructed instance becomes active.
// ------------------------------------------------------------------
extern TCPMessenger* _tcpMessengerSingleton;

#endif // TCP_MESSENGER_H