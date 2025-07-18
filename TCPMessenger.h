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
// PAYLOAD SIZE CAP  (adjust here – affects all peers)
// ------------------------------------------------------------------
#ifndef TCPMSG_MAX_PAYLOAD_ENCRYPTED   // absolute payload limit *after* encryption
#define TCPMSG_MAX_PAYLOAD_ENCRYPTED  2048u   // 2 kB hard cap
#endif

//default port
static constexpr uint16_t TCPMSG_DEFAULT_PORT = 12345; // default port for TCP Messenger

static constexpr uint16_t TCPMSG_STATIC_RXBUF = 255u;   // bytes kept on the stack
static_assert(TCPMSG_STATIC_RXBUF < TCPMSG_MAX_PAYLOAD_ENCRYPTED,
              "static buffer must be smaller than hard cap");

static constexpr uint8_t  TCPMSG_ID_BROADCAST = 0xFF;

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
// Remote info passed to callbacks
// ------------------------------------------------------------------
struct TCPMsgRemoteInfo {
    IPAddress ip;
    uint16_t  port;
    String    host;   // may be empty
};

// ------------------------------------------------------------------
// Callback signatures  
// ------------------------------------------------------------------
using TCPMsgReceiveCB =
    std::function<void(const TCPMsgRemoteInfo& from,
                       uint8_t type,
                       uint8_t chanId,
                       const uint8_t* payload,
                       uint16_t len)>;                 // <-- widened

using TCPMsgSendDoneCB =
    std::function<void(TCPMsgResult rc,
                       const TCPMsgRemoteInfo& to,
                       uint8_t type,
                       uint8_t chanId,
                       uint16_t lenPlain)>;            // <-- widened

// ------------------------------------------------------------------
// TCPMessenger (singleton)
// ------------------------------------------------------------------
class TCPMessenger {
public:
    explicit TCPMessenger(EncryptionHandler* enc = nullptr);
    ~TCPMessenger();

    TCPMessenger(const TCPMessenger&)            = delete;
    TCPMessenger& operator=(const TCPMessenger&) = delete;

    bool beginServer(uint16_t port = TCPMSG_DEFAULT_PORT);// default port
    void endServer();
    bool serverActive() const { return server_ != nullptr; }
    uint16_t serverPort() const { return serverPort_; }

    // --- by IP ------------------------------------------------
    TCPMsgResult sendToIP(const Serializable& msg,
                          uint8_t            chanId,
                          const IPAddress&   ip,
                          uint16_t           port = TCPMSG_DEFAULT_PORT);
    
    // broadcast convenience
    inline TCPMsgResult sendToIP(const Serializable& msg,
                                 const IPAddress&   ip,
                                 uint16_t           port = TCPMSG_DEFAULT_PORT)
    {
        return sendToIP(msg, TCPMSG_ID_BROADCAST, ip, port);
    }
    
    // --- by host (C-string) -----------------------------------
    TCPMsgResult sendToHost(const Serializable& msg,
                            uint8_t            chanId,
                            const char*        host,
                            uint16_t           port = TCPMSG_DEFAULT_PORT);
    
    // broadcast convenience
    inline TCPMsgResult sendToHost(const Serializable& msg,
                                   const char*        host,
                                   uint16_t           port = TCPMSG_DEFAULT_PORT)
    {
        return sendToHost(msg, TCPMSG_ID_BROADCAST, host, port);
    }
    
    // --- by host (Arduino String) -----------------------------
    inline TCPMsgResult sendToHost(const Serializable& msg,
                                   uint8_t            chanId,
                                   const String&      host,
                                   uint16_t           port = TCPMSG_DEFAULT_PORT)
    {
        return sendToHost(msg, chanId, host.c_str(), port);
    }
    
    inline TCPMsgResult sendToHost(const Serializable& msg,
                                   const String&      host,
                                   uint16_t           port = TCPMSG_DEFAULT_PORT)
    {
        return sendToHost(msg, TCPMSG_ID_BROADCAST, host.c_str(), port);
    }

    void onReceive (TCPMsgReceiveCB cb) { recvCB_  = cb; }
    void onSendDone(TCPMsgSendDoneCB cb) { sendDoneCB_ = cb; }

    void loop();   // no-op (kept for symmetry)

private:
    // ----------------------- per-client context ------------------------------
    struct ClientCtx {
        AsyncClient* client;
        TCPMsgRemoteInfo remote;

        uint8_t   headerPos;   // 0..3 while reading header
        uint8_t   rxType;
        uint8_t   rxChan;
        uint16_t  rxLen;       // encrypted length (16-bit)
        uint16_t  rxPos;

        uint8_t   rxBufStatic[TCPMSG_STATIC_RXBUF];
        std::vector<uint8_t> rxBufDyn;
        bool      useDyn;

        explicit ClientCtx(AsyncClient* c)
        : client(c), headerPos(0), rxType(0), rxChan(0),
          rxLen(0), rxPos(0), useDyn(false) {}
    };

    // linked list
    struct ClientNode { ClientCtx* ctx; ClientNode* next; };

    ClientCtx* addCtx(AsyncClient* c, const IPAddress& ip, uint16_t port);
    void       removeCtx(AsyncClient* c);
    void       handleNewClient(AsyncClient* client);

    // Async callbacks (static forwarders) …
    static void _onClientData     (void* arg, AsyncClient* c, void* data, size_t len);
    static void _onClientDisconnect(void* arg, AsyncClient* c);
    static void _onClientError    (void* arg, AsyncClient* c, int8_t error);
    static void _onClientTimeout  (void* arg, AsyncClient* c, uint32_t time);
    static void _onClientPoll     (void* arg, AsyncClient* c);

    // instance handlers
    void onClientData     (ClientCtx* ctx, const uint8_t* data, size_t len);
    void onClientDisconnect(ClientCtx* ctx);
    void onClientError    (ClientCtx* ctx, int8_t error);
    void onClientTimeout  (ClientCtx* ctx, uint32_t time);
    void onClientPoll     (ClientCtx* ctx);

    // frame handling
    void parseBytes(ClientCtx* ctx, const uint8_t* data, size_t len);
    void dispatchFrame(const TCPMsgRemoteInfo& from,
                       uint8_t type, uint8_t chan,
                       const uint8_t* encPayload, uint16_t encLen);

    // send path helpers
    TCPMsgResult buildPlain(const Serializable& msg,
                            std::vector<uint8_t>& outPlain,
                            uint8_t& outType);
    TCPMsgResult encryptPayload(std::vector<uint8_t>& buf);
    bool         resolveHost(const char* host, IPAddress& outIP);
    TCPMsgResult sendFrame(const TCPMsgRemoteInfo& to,
                           uint8_t type, uint8_t chan,
                           const uint8_t* encPayload, uint16_t encLen);

    struct OutboundCtx {
        AsyncClient* client;
        TCPMsgRemoteInfo to;
        uint8_t   type;
        uint8_t   chan;
        uint16_t  encLen;
        std::vector<uint8_t> frame;
        TCPMessenger* self;
        OutboundCtx() : client(nullptr), type(0), chan(0),
                        encLen(0), self(nullptr) {}
    };
    static void _onOutboundConnect   (void* arg, AsyncClient* c);
    static void _onOutboundError     (void* arg, AsyncClient* c, int8_t error);
    static void _onOutboundDisconnect(void* arg, AsyncClient* c);

    void onOutboundConnect   (OutboundCtx* ctx, AsyncClient* c);
    void onOutboundError     (OutboundCtx* ctx, AsyncClient* c, int8_t error);
    void onOutboundDisconnect(OutboundCtx* ctx, AsyncClient* c);

    void notifySendDone(TCPMsgResult rc, const TCPMsgRemoteInfo& to,
                        uint8_t type, uint8_t chan, uint16_t plainLen);

private:
    EncryptionHandler* enc_;
    AsyncServer*       server_;
    uint16_t           serverPort_;
    ClientNode*        head_;

    TCPMsgReceiveCB  recvCB_;
    TCPMsgSendDoneCB sendDoneCB_;
};

extern TCPMessenger* _tcpMessengerSingleton;

#endif // TCP_MESSENGER_H