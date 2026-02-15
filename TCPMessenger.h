#ifndef TCP_MESSENGER_H
#define TCP_MESSENGER_H

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <Arduino.h>
#include <stdint.h>
#include <functional>
#include <vector>
#include <cstring> // memcpy, memcmp

#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPmDNS.h>

#include "Serializable.h"
#include "EncryptionHandler.h"
#include "MDNSSniffer.h"
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
static constexpr uint8_t  TCPMSG_TYPE_ACK = 0xFE;
static constexpr uint32_t TCPMSG_ACK_TIMEOUT_MS = 500u;
static constexpr uint16_t TCPMSG_FRAME_HEADER_LEN = 4u;
static constexpr uint16_t TCPMSG_ENVELOPE_HEADER_LEN = 14u;
static constexpr uint16_t TCPMSG_ACK_PLAIN_LEN = 10u;

static constexpr uint8_t TCPMSG_ACK_CODE_OK  = 0;
static constexpr uint8_t TCPMSG_ACK_CODE_ERR = 1;
static constexpr uint8_t TCPMSG_ACK_FLAG_WRONG_DST     = 0x01;
static constexpr uint8_t TCPMSG_ACK_FLAG_BAD_FORMAT    = 0x02;
static constexpr uint8_t TCPMSG_ACK_FLAG_INTERNAL_ERROR= 0x04;


// ------------------------------------------------------------------
// Helper classes
// ------------------------------------------------------------------
class MACAddress {
public:
    MACAddress() : bytes_{0,0,0,0,0,0} {}

    // only accepts a real uint8_t[6] lvalue
    explicit MACAddress(const uint8_t (&b)[6]) { memcpy(bytes_, b, 6); }

    void setBytes(const uint8_t* p) {
        if (p) memcpy(bytes_, p, 6);
    }

    bool isZero() const {
        static const uint8_t z[6] = {0,0,0,0,0,0};
        return memcmp(bytes_, z, 6) == 0;
    }

    const uint8_t* data() const { return bytes_; }

    bool operator==(const MACAddress& o) const { return memcmp(bytes_, o.bytes_, 6) == 0; }
    bool operator!=(const MACAddress& o) const { return !(*this == o); }

private:
    uint8_t bytes_[6];
};



// ------------------------------------------------------------------
// Result codes
// ------------------------------------------------------------------
enum TCPMsgResult : uint8_t {
    TCPMSG_OK = 0,
    TCPMSG_ERR_NOT_CONNECTED, //1
    TCPMSG_ERR_RESOLVE, //2
    TCPMSG_ERR_TOO_LARGE, //3
    TCPMSG_ERR_ENCRYPT, //4
    TCPMSG_ERR_WRITE,
    TCPMSG_ERR_TRANSPORT,
    TCPMSG_ERR_DECODE, //7
    TCPMSG_QUEUED,  // queued for sending
    TCPMSG_ERR_BUSY, // busy with another send
    TCPMSG_ERR_WRONGDSTMAC,
    TCPMSG_ERR_ACK_TIMEOUT,
    TCPMSG_ERR_ACK,
};



// ------------------------------------------------------------------
// Remote info passed to callbacks
// ------------------------------------------------------------------
struct TCPMsgRemoteInfo {
    IPAddress ip;
    uint16_t  port;
    String    host;   // may be empty
    MACAddress mac;   // sender MAC from envelope (inbound)
    uint16_t  seq = 0;                 // envelope seq (inbound)
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

    struct PendingSend {
        std::vector<uint8_t> frame;   // header + encrypted payload
        TCPMsgRemoteInfo     to;      // ip/host/port (host may still need DNS)
        bool                 needResolve=false;
        MACAddress           expectedDstMac;
        uint16_t             seq = 0;
        uint16_t             plainLen = 0;
    };

    explicit TCPMessenger(EncryptionHandler* enc = nullptr);
    ~TCPMessenger();

    void begin(){
        cacheLocalMac();
        mdnsSniffer_.begin();
        beginServer(TCPMSG_DEFAULT_PORT);
    }

    TCPMessenger(const TCPMessenger&)            = delete;
    TCPMessenger& operator=(const TCPMessenger&) = delete;

    bool beginServer(uint16_t port = TCPMSG_DEFAULT_PORT);// default port
    void endServer();
    bool serverActive() const { return server_ != nullptr; }
    uint16_t serverPort() const { return serverPort_; }


    TCPMsgResult sendToHost(const Serializable& m,
                        uint8_t chan,
                        const char* host,
                        const MACAddress& expectedDstMac,
                        uint16_t port = TCPMSG_DEFAULT_PORT)
    {
        return sendTo(m, chan, host, IPAddress(), expectedDstMac, port, /*needResolve=*/true);
    }
    //overwrite for Arduino string
    TCPMsgResult sendToHost(const Serializable& m,
                        uint8_t chan,
                        const String& host,
                        const MACAddress& expectedDstMac,
                        uint16_t port = TCPMSG_DEFAULT_PORT)
    {
        return sendToHost(m, chan, host.c_str(), expectedDstMac, port);
    }
    
    TCPMsgResult sendToIP(const Serializable& m,
                          uint8_t chan,
                          const IPAddress& ip,
                          const MACAddress& expectedDstMac,
                          uint16_t port = TCPMSG_DEFAULT_PORT)
    {
        return sendTo(m, chan, /*hostStr=*/nullptr, ip, expectedDstMac, port, /*needResolve=*/false);
    }


    void onReceive (TCPMsgReceiveCB cb) { recvCB_  = cb; }
    void onSendDone(TCPMsgSendDoneCB cb) { sendDoneCB_ = cb; }
    bool isBusy() const { return sendBusy_; }
    bool lastSendOk() const { return lastSendOk_; }
    uint8_t lastSendFlags() const { return lastSendFlags_; }
    const MACAddress& lastAckMac() const { return lastAckMac_; }
    uint16_t lastSendSeq() const { return lastSendSeq_; }

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
        bool      closing;

        explicit ClientCtx(AsyncClient* c)
        : client(c), headerPos(0), rxType(0), rxChan(0),
          rxLen(0), rxPos(0), useDyn(false), closing(false) {}
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
    void dispatchFrame(ClientCtx* ctx,
                       uint8_t type, uint8_t chan,
                       const uint8_t* encPayload, uint16_t encLen);
    void sendAckInline(AsyncClient* client, uint8_t chan, uint16_t seq,
                       uint8_t ackCode, uint8_t flags, const MACAddress& rxMac);
    void buildEnvelope(const MACAddress& srcMac, const MACAddress& dstMac, uint16_t seq,
                       const std::vector<uint8_t>& appPayload,
                       std::vector<uint8_t>& outPlain);
    bool parseEnvelope(const uint8_t* plain, uint16_t len,
                       const uint8_t*& appPayload, uint16_t& appLen,
                       uint16_t& seq, MACAddress& srcMac, MACAddress& dstMac) const;
    const MACAddress& getLocalMac() const;
    void cacheLocalMac();

    TCPMsgResult buildPlain(const Serializable& msg,
                            std::vector<uint8_t>& outPlain,
                            uint8_t& outType);
    TCPMsgResult encryptPayload(std::vector<uint8_t>& buf);
    bool         resolveHost(const char* host, IPAddress& outIP);
    TCPMsgResult sendFrame(const TCPMsgRemoteInfo& to,
                           uint8_t type, uint8_t chan,
                           const uint8_t* encPayload, uint16_t encLen,
                           uint16_t seq, uint16_t plainLen);

    struct OutboundCtx {
        AsyncClient* client;
        TCPMsgRemoteInfo to;
        uint8_t   type;
        uint8_t   chan;
        uint16_t  encLen;
        uint16_t  plainLen;
        uint16_t  seq;
        std::vector<uint8_t> frame;
        uint8_t   headerPos;
        uint8_t   rxType;
        uint8_t   rxChan;
        uint16_t  rxLen;
        uint16_t  rxPos;
        uint8_t   rxBufStatic[TCPMSG_STATIC_RXBUF];
        std::vector<uint8_t> rxBufDyn;
        bool      useDyn;
        bool      requestWritten;
        bool      completed;
        uint32_t  waitStartMs;
        TCPMessenger* self;
        OutboundCtx() : client(nullptr), type(0), chan(0),
                        encLen(0), plainLen(0), seq(0),
                        headerPos(0), rxType(0), rxChan(0),
                        rxLen(0), rxPos(0), useDyn(false),
                        requestWritten(false), completed(false), waitStartMs(0),
                        self(nullptr) {}
    };
    static void _onOutboundConnect   (void* arg, AsyncClient* c);
    static void _onOutboundError     (void* arg, AsyncClient* c, int8_t error);
    static void _onOutboundDisconnect(void* arg, AsyncClient* c);
    static void _onOutboundData      (void* arg, AsyncClient* c, void* data, size_t len);
    static void _onOutboundTimeout   (void* arg, AsyncClient* c, uint32_t time);
    static void _onOutboundPoll      (void* arg, AsyncClient* c);

    void onOutboundConnect   (OutboundCtx* ctx, AsyncClient* c);
    void onOutboundError     (OutboundCtx* ctx, AsyncClient* c, int8_t error);
    void onOutboundDisconnect(OutboundCtx* ctx, AsyncClient* c);
    void onOutboundData      (OutboundCtx* ctx, AsyncClient* c, const uint8_t* data, size_t len);
    void onOutboundTimeout   (OutboundCtx* ctx, AsyncClient* c, uint32_t time);
    void onOutboundPoll      (OutboundCtx* ctx, AsyncClient* c);

    void notifySendDone(TCPMsgResult rc, const TCPMsgRemoteInfo& to,
                        uint8_t type, uint8_t chan, uint16_t plainLen);

private:

    /*  private
     *  ------------------------------------------------------------------
     *  hostStr  – may be nullptr/empty when you already have an IP
     *  ip       – ignored when needResolve==true
     *  needResolve – true  ➞ resolve hostStr first
     *                 false ➞ use ip directly
     */
    TCPMsgResult sendTo(const Serializable& msg,
                        uint8_t             chan,
                        const char*         hostStr,
                        const IPAddress&    ip,
                        const MACAddress&   expectedDstMac,
                        uint16_t            port,
                        bool                needResolve);

    void            clearPending();           // resets slot + busy flag
    static void     _sendWorkerThunk(void*);  // FreeRTOS task entry
    void            sendWorkerLoop();         // actual loop body

    EncryptionHandler* enc_;
    AsyncServer*       server_;
    uint16_t           serverPort_;
    ClientNode*        head_;

    TCPMsgReceiveCB  recvCB_;
    TCPMsgSendDoneCB sendDoneCB_;

    SemaphoreHandle_t sendMtx_;
    TaskHandle_t      sendWorker_;
    bool              sendBusy_;
    PendingSend       pending_;
    bool              taskRunning_;
    uint16_t          nextSeq_ = 1;
    bool              lastSendOk_ = false;
    uint8_t           lastSendFlags_ = 0;
    MACAddress        lastAckMac_;
    uint16_t          lastSendSeq_ = 0;
    MACAddress        localMac_;

    //for better callbacks

    // --- receive worker plumbing ---
    struct RecvItem {
        TCPMsgRemoteInfo from;
        uint8_t  type;
        uint8_t  chan;
        uint16_t len;     // encrypted or plain bytes in data
        uint8_t* data;    // pvPortMalloc'd buffer of length 'len' (or nullptr if len==0)
        bool     isEncrypted; // true if 'data' is encrypted and needs decrypt in worker
    };
    
    static constexpr UBaseType_t TCPMSG_RX_QUEUE_DEPTH = 16;  // tune
    QueueHandle_t   rxQueue_   = nullptr;
    TaskHandle_t    rxWorker_  = nullptr;
    
    static void     _rxWorkerThunk(void*);
    void            rxWorkerLoop();

    MDNSSniffer mdnsSniffer_;
};

extern TCPMessenger* _tcpMessengerSingleton;

#endif // TCP_MESSENGER_H
