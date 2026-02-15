#include "TCPMessenger.h"
#include <cstring>        // memcpy
#include <LoggingBase.h>  // provides gLogger

#include <lwip/sockets.h>   // <- add once, e.g. at top of file
#include <lwip/netdb.h>

// ------------------------------------------------------------------
// Optional logging macro (compiles away if gLogger not defined).
// ------------------------------------------------------------------
#ifdef gLogger
  #define TCPMSG_LOG(msg) do{ gLogger->println(F(msg)); }while(0)
#else
  #define TCPMSG_LOG(msg) do{}while(0)
#endif

// ------------------------------------------------------------------
// Global singleton
// ------------------------------------------------------------------
TCPMessenger* _tcpMessengerSingleton = nullptr;


// ------------------------------------------------------------------
// Constructor / destructor
// ------------------------------------------------------------------
TCPMessenger::TCPMessenger(EncryptionHandler* enc)
: enc_(enc),
  server_(nullptr),
  serverPort_(0),
  head_(nullptr),
  recvCB_(nullptr),
  sendDoneCB_(nullptr)
{
    if (_tcpMessengerSingleton && _tcpMessengerSingleton != this) {
        TCPMSG_LOG("TCPMessenger: singleton already exists; additional instance unsupported.");
        return;
    }
    _tcpMessengerSingleton = this;

    sendMtx_     = xSemaphoreCreateMutex();
    sendBusy_    = false;
    
    xTaskCreatePinnedToCore(
            _sendWorkerThunk,        // entry
            "TCPMsgW",
            4096,
            this,
            1,                       // low prio
            &sendWorker_,
            1);                      // APP CPU
    taskRunning_ = true;

    rxQueue_ = xQueueCreate(TCPMSG_RX_QUEUE_DEPTH, sizeof(RecvItem*));
    if (!rxQueue_) {
        TCPMSG_LOG("TCPMessenger: RX queue create failed");
    } else {
        xTaskCreatePinnedToCore(_rxWorkerThunk, "TCPMsgRX",
                                4096, this, 1, &rxWorker_, tskNO_AFFINITY);
    }
}


TCPMessenger::~TCPMessenger() {
    endServer();
    if (_tcpMessengerSingleton == this) {
        _tcpMessengerSingleton = nullptr;
    }
    // stop RX worker
    if (rxWorker_) {
        RecvItem* poison = nullptr;
        xQueueSendToBack(rxQueue_, &poison, 0);   // wake + stop
        vTaskDelay(10);                             // yield to let it exit
        rxWorker_ = nullptr;                       // (worker self-deletes)
    }
    if (rxQueue_) {
        // drain leftovers defensively
        RecvItem* it = nullptr;
        while (xQueueReceive(rxQueue_, &it, 0) == pdTRUE) {
            if (it) { if (it->data) vPortFree(it->data); delete it; }
        }
        vQueueDelete(rxQueue_);
        rxQueue_ = nullptr;
    }

    taskRunning_ = false;
    xTaskNotifyGive(sendWorker_);   // wake so it can exit
    vTaskDelay(1);                  // yield to let it clean up (tiny)
    vSemaphoreDelete(sendMtx_);

    

}


// ------------------------------------------------------------------
// Server start/stop
// ------------------------------------------------------------------
bool TCPMessenger::beginServer(uint16_t port) {
    endServer();  // clean slate

    server_ = new AsyncServer(port);
    if (!server_) return false;
    serverPort_ = port;

    // register accept handler
    server_->onClient([](void* /*arg*/, AsyncClient* client){
        if (_tcpMessengerSingleton) {
            _tcpMessengerSingleton->handleNewClient(client);
        } else {
            if (client) { client->close(true); delete client; }
        }
    }, nullptr);

    server_->begin();
    return true;
}


void TCPMessenger::endServer() {
    // clean up all client contexts
    ClientNode* n = head_;
    while (n) {
        ClientNode* next = n->next;
        if (n->ctx) {
            if (n->ctx->client) {
                n->ctx->client->onData(nullptr,nullptr);
                n->ctx->client->onDisconnect(nullptr,nullptr);
                n->ctx->client->onError(nullptr,nullptr);
                n->ctx->client->onTimeout(nullptr,nullptr);
                n->ctx->client->onPoll(nullptr,nullptr);
                n->ctx->client->close(true);
                delete n->ctx->client;
            }
            delete n->ctx;
        }
        delete n;
        n = next;
    }
    head_ = nullptr;

    if (server_) {
        delete server_;
        server_ = nullptr;
    }
    serverPort_ = 0;
}


// ------------------------------------------------------------------
// Handle new inbound TCP client
// ------------------------------------------------------------------
void TCPMessenger::handleNewClient(AsyncClient* client) {
    if (!client) return;

    // reduce latency on tiny frames
    client->setNoDelay(true);

    IPAddress ip   = client->remoteIP();
    uint16_t port  = client->remotePort();

    ClientCtx* ctx = addCtx(client, ip, port);
    if (!ctx) {
        client->close(true);
        delete client;
        return;
    }

    // attach event handlers, passing ctx as arg
    client->onData(&_onClientData, ctx);
    client->onDisconnect(&_onClientDisconnect, ctx);
    client->onError(&_onClientError, ctx);
    client->onTimeout(&_onClientTimeout, ctx);
    client->onPoll(&_onClientPoll, ctx);
}


// ------------------------------------------------------------------
// Linked-list context mgmt
// ------------------------------------------------------------------
TCPMessenger::ClientCtx* TCPMessenger::addCtx(AsyncClient* c,
                                              const IPAddress& ip,
                                              uint16_t port) {
    ClientCtx* ctx = new ClientCtx(c);
    if (!ctx) return nullptr;
    ctx->remote.ip   = ip;
    ctx->remote.port = port;
    ctx->remote.host = ""; // unknown for inbound connections

    ClientNode* node = new ClientNode{ctx, head_};
    if (!node) {
        delete ctx;
        return nullptr;
    }
    head_ = node;
    return ctx;
}

void TCPMessenger::removeCtx(AsyncClient* c) {
    ClientNode** pp = &head_;
    while (*pp) {
        if ((*pp)->ctx && (*pp)->ctx->client == c) {
            ClientNode* dead = *pp;
            *pp = dead->next;
            delete dead->ctx;
            delete dead;
            return;
        }
        pp = &((*pp)->next);
    }
}


// ------------------------------------------------------------------
// Static forwarders for server-accepted client events
// ------------------------------------------------------------------
void TCPMessenger::_onClientData(void* arg, AsyncClient* /*c*/, void* data, size_t len) {
    ClientCtx* ctx = reinterpret_cast<ClientCtx*>(arg);
    if (_tcpMessengerSingleton && ctx) {
        _tcpMessengerSingleton->onClientData(ctx, static_cast<const uint8_t*>(data), len);
    }
}

void TCPMessenger::_onClientDisconnect(void* arg, AsyncClient* /*c*/) {
    ClientCtx* ctx = reinterpret_cast<ClientCtx*>(arg);
    if (_tcpMessengerSingleton && ctx) {
        _tcpMessengerSingleton->onClientDisconnect(ctx);
    }
}

void TCPMessenger::_onClientError(void* arg, AsyncClient* /*c*/, int8_t error) {
    ClientCtx* ctx = reinterpret_cast<ClientCtx*>(arg);
    if (_tcpMessengerSingleton && ctx) {
        _tcpMessengerSingleton->onClientError(ctx, error);
    }
}

void TCPMessenger::_onClientTimeout(void* arg, AsyncClient* /*c*/, uint32_t time) {
    ClientCtx* ctx = reinterpret_cast<ClientCtx*>(arg);
    if (_tcpMessengerSingleton && ctx) {
        _tcpMessengerSingleton->onClientTimeout(ctx, time);
    }
}

void TCPMessenger::_onClientPoll(void* arg, AsyncClient* /*c*/) {
    ClientCtx* ctx = reinterpret_cast<ClientCtx*>(arg);
    if (_tcpMessengerSingleton && ctx) {
        _tcpMessengerSingleton->onClientPoll(ctx);
    }
}


// ------------------------------------------------------------------
// Instance-side client event handlers
// ------------------------------------------------------------------
void TCPMessenger::onClientData(ClientCtx* ctx, const uint8_t* data, size_t len) {
    if (!ctx) return;
    parseBytes(ctx, data, len);
}

void TCPMessenger::onClientDisconnect(ClientCtx* ctx) {
    if (!ctx) return;
    AsyncClient* c = ctx->client;
    removeCtx(c);
    if (c) {
        c->close(true);
        delete c;
    }
}

void TCPMessenger::onClientError(ClientCtx* ctx, int8_t /*error*/) {
    if (!ctx) return;
    // treat as disconnect
    onClientDisconnect(ctx);
}

void TCPMessenger::onClientTimeout(ClientCtx* ctx, uint32_t /*time*/) {
    if (!ctx) return;
    onClientDisconnect(ctx);
}

void TCPMessenger::onClientPoll(ClientCtx* /*ctx*/) {
    // no-op; you could drop idle clients here
}


// ------------------------------------------------------------------
// Parse framed bytes for server clients
// Header bytes: type, chanId, encLen
// ------------------------------------------------------------------
void TCPMessenger::parseBytes(ClientCtx* ctx, const uint8_t* data, size_t len)
{
    while (len--) {
        uint8_t b = *data++;

        // ---- header collection (4 bytes) ----
        if (ctx->headerPos < 4) {
            switch (ctx->headerPos) {
                case 0: ctx->rxType = b; break;
                case 1: ctx->rxChan = b; break;
                case 2: ctx->rxLen  = b; break;           // low byte
                case 3: ctx->rxLen |= static_cast<uint16_t>(b) << 8; break; // hi byte
            }
            ctx->headerPos++;

            if (ctx->headerPos == 4) {                    // header complete
                if (ctx->rxLen == 0) {                    // empty payload
                    dispatchFrame(ctx, ctx->rxType, ctx->rxChan, nullptr, 0);
                    ctx->headerPos = 0;
                } else if (ctx->rxLen > TCPMSG_MAX_PAYLOAD_ENCRYPTED) {
                    ctx->client->close(true);             // hard cap violated
                    return;
                } else {
                    ctx->useDyn = (ctx->rxLen > TCPMSG_STATIC_RXBUF);
                    if (ctx->useDyn) ctx->rxBufDyn.resize(ctx->rxLen);
                    ctx->rxPos = 0;
                }
            }
            continue;
        }

        // ---- payload collection ----
        uint8_t* dest = ctx->useDyn ? ctx->rxBufDyn.data() : ctx->rxBufStatic;
        dest[ctx->rxPos++] = b;

        if (ctx->rxPos >= ctx->rxLen) {   // full frame ready
            dispatchFrame(ctx, ctx->rxType, ctx->rxChan,
                          dest, ctx->rxLen);
            ctx->headerPos = 0;           // reset for next frame
        }
    }
}


// ------------------------------------------------------------------
// Dispatch a received frame (decrypt + user callback)
// ------------------------------------------------------------------
void TCPMessenger::dispatchFrame(ClientCtx* ctx,
                                 uint8_t  type,
                                 uint8_t  chanId,
                                 const uint8_t* encPayload,
                                 uint16_t encLen)          // <-- widened
{
    if (!ctx) return;
    if (type == TCPMSG_TYPE_ACK) return;

    uint8_t myMac[6] = {0,0,0,0,0,0};
    getLocalMac(myMac);

    std::vector<uint8_t> plain;
    if (enc_ && encLen) {
        std::vector<uint8_t> encVec(encPayload, encPayload + encLen);
        if (!enc_->decrypt(encVec, plain)) {
            sendAckInline(ctx->client, chanId, 0, TCPMSG_ACK_CODE_ERR,
                          TCPMSG_ACK_FLAG_BAD_FORMAT, myMac);
            return;
        }
    } else if (enc_ && !encLen) {
        sendAckInline(ctx->client, chanId, 0, TCPMSG_ACK_CODE_ERR,
                      TCPMSG_ACK_FLAG_BAD_FORMAT, myMac);
        return;
    } else {
        if (encLen) plain.assign(encPayload, encPayload + encLen);
    }

    const uint8_t* appPayload = nullptr;
    uint16_t appLen = 0;
    uint16_t seq = 0;
    uint8_t srcMac[6] = {0,0,0,0,0,0};
    uint8_t dstMac[6] = {0,0,0,0,0,0};

    if (!parseEnvelope(plain.data(), static_cast<uint16_t>(plain.size()),
                       appPayload, appLen, seq, srcMac, dstMac)) {
        sendAckInline(ctx->client, chanId, 0, TCPMSG_ACK_CODE_ERR,
                      TCPMSG_ACK_FLAG_BAD_FORMAT, myMac);
        return;
    }

    if (memcmp(dstMac, myMac, sizeof(myMac)) != 0) {
        sendAckInline(ctx->client, chanId, seq, TCPMSG_ACK_CODE_ERR,
                      TCPMSG_ACK_FLAG_WRONG_DST, myMac);
        return;
    }

    // Allocate item
    RecvItem* it = new RecvItem();
    if (!it) {
        sendAckInline(ctx->client, chanId, seq, TCPMSG_ACK_CODE_ERR,
                      TCPMSG_ACK_FLAG_INTERNAL_ERROR, myMac);
        return;
    }
    it->from        = ctx->remote;
    it->type        = type;
    it->chan        = chanId;
    it->len         = appLen;
    it->isEncrypted = false;
    it->data        = nullptr;

    if (appLen) {
        it->data = static_cast<uint8_t*>(pvPortMalloc(appLen));
        if (!it->data) {
            delete it;
            sendAckInline(ctx->client, chanId, seq, TCPMSG_ACK_CODE_ERR,
                          TCPMSG_ACK_FLAG_INTERNAL_ERROR, myMac);
            return;
        }
        memcpy(it->data, appPayload, appLen);
    }

    bool queued = false;
    if (rxQueue_ && xQueueSendToBack(rxQueue_, &it, 0) == pdTRUE) {
        queued = true;
    } else {
        RecvItem* old = nullptr;
        if (rxQueue_ && xQueueReceive(rxQueue_, &old, 0) == pdTRUE) {
            if (old) { if (old->data) vPortFree(old->data); delete old; }
            if (xQueueSendToBack(rxQueue_, &it, 0) == pdTRUE) {
                queued = true;
            }
        }
    }

    if (!queued) {
        if (it->data) vPortFree(it->data);
        delete it;
        sendAckInline(ctx->client, chanId, seq, TCPMSG_ACK_CODE_ERR,
                      TCPMSG_ACK_FLAG_INTERNAL_ERROR, myMac);
        return;
    }

    sendAckInline(ctx->client, chanId, seq, TCPMSG_ACK_CODE_OK, 0, myMac);
}

void TCPMessenger::buildEnvelope(const uint8_t srcMac[6], const uint8_t dstMac[6], uint16_t seq,
                                 const std::vector<uint8_t>& appPayload,
                                 std::vector<uint8_t>& outPlain) {
    outPlain.resize(14u + appPayload.size());
    memcpy(&outPlain[0], srcMac, 6);
    memcpy(&outPlain[6], dstMac, 6);
    outPlain[12] = static_cast<uint8_t>(seq & 0xFF);
    outPlain[13] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    if (!appPayload.empty()) {
        memcpy(&outPlain[14], appPayload.data(), appPayload.size());
    }
}

bool TCPMessenger::parseEnvelope(const uint8_t* plain, uint16_t len,
                                 const uint8_t*& appPayload, uint16_t& appLen,
                                 uint16_t& seq, uint8_t srcMac[6], uint8_t dstMac[6]) const {
    if (!plain || len < 14) return false;
    memcpy(srcMac, &plain[0], 6);
    memcpy(dstMac, &plain[6], 6);
    seq = static_cast<uint16_t>(plain[12]) |
          (static_cast<uint16_t>(plain[13]) << 8);
    appPayload = &plain[14];
    appLen = static_cast<uint16_t>(len - 14);
    return true;
}

void TCPMessenger::getLocalMac(uint8_t out[6]) const {
    if (!out) return;
    WiFi.macAddress(out);
}

void TCPMessenger::sendAckInline(AsyncClient* client, uint8_t chan, uint16_t seq,
                                 uint8_t ackCode, uint8_t flags,
                                 const uint8_t rxMac[6]) {
    if (!client) return;
    uint8_t payload[10];
    payload[0] = static_cast<uint8_t>(seq & 0xFF);
    payload[1] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    payload[2] = ackCode;
    payload[3] = flags;
    memcpy(&payload[4], rxMac, 6);

    std::vector<uint8_t> wire(payload, payload + sizeof(payload));
    if (enc_) {
        std::vector<uint8_t> encrypted = enc_->encrypt(wire);
        wire.swap(encrypted);
    }

    std::vector<uint8_t> frame(4 + wire.size());
    frame[0] = TCPMSG_TYPE_ACK;
    frame[1] = chan;
    frame[2] = static_cast<uint8_t>(wire.size() & 0xFF);
    frame[3] = static_cast<uint8_t>((wire.size() >> 8) & 0xFF);
    if (!wire.empty()) memcpy(&frame[4], wire.data(), wire.size());

    size_t written = client->write(reinterpret_cast<const char*>(frame.data()), frame.size());
    if (written == frame.size()) {
        client->send();
    }
}


// ------------------------------------------------------------------
// Build plaintext payload from Serializable
// ------------------------------------------------------------------
TCPMsgResult TCPMessenger::buildPlain(const Serializable& msg,
                                      std::vector<uint8_t>& outPlain,
                                      uint8_t& outType)
{
    outType = msg.typeId();
    uint16_t plainLen = msg.payloadSize();

    // Guard: after encryption must still fit in 16-bit length
    size_t encMax = plainLen + (enc_ ? EncryptionHandler::CHECKSUM_SIZE : 0);
    if (encMax > TCPMSG_MAX_PAYLOAD_ENCRYPTED) {
        return TCPMSG_ERR_TOO_LARGE;
    }

    outPlain.resize(plainLen);
    if (plainLen) {
        msg.serializeTo(outPlain.data());
    }
    return TCPMSG_OK;
}


// ------------------------------------------------------------------
// Encrypt payload (payload only; header unencrypted)
// ------------------------------------------------------------------
TCPMsgResult TCPMessenger::encryptPayload(std::vector<uint8_t>& buf) {
    if (!enc_) return TCPMSG_OK;
    std::vector<uint8_t> encrypted = enc_->encrypt(buf);
    buf.swap(encrypted);
    return TCPMSG_OK;
}


// ------------------------------------------------------------------
// Resolve host: mDNS first (.local), then WiFi DNS
// Case-insensitive ".local" avoided (assume user passes lower-case).
// ------------------------------------------------------------------
bool TCPMessenger::resolveHost(const char* host, IPAddress& outIP) {
    if (!host || !*host) return false;

    // simple suffix check
    size_t len = strlen(host);
    if (len > 6 && host[len-6] == '.' &&
        host[len-5] == 'l' && host[len-4] == 'o' &&
        host[len-3] == 'c' && host[len-2] == 'a' && host[len-1] == 'l') {

        String h = String(host).substring(0, len - 6);
        IPAddress ip = MDNS.queryHost(h);
        if (ip != (uint32_t)0) {
            outIP = ip;
            return true;
        }
        // fall through to DNS
    }

    if (WiFi.hostByName(host, outIP) == 1) {
        return true;
    }
    return false;
}


// ------------------------------------------------------------------
// private send: by hostname or IP
// ------------------------------------------------------------------
TCPMsgResult TCPMessenger::sendTo(const Serializable& msg,
                                          uint8_t             chan,
                                          const char*         hostStr,
                                          const IPAddress&    ip,
                                          const uint8_t       expectedDstMac[6],
                                          uint16_t            port,
                                          bool                needResolve)
{
    /* ---------- fast local work: build + encrypt ------------------- */
    std::vector<uint8_t> appPlain;
    uint8_t type = 0;
    TCPMsgResult rc = buildPlain(msg, appPlain, type);
    if (rc != TCPMSG_OK) return rc;

    uint8_t srcMac[6] = {0,0,0,0,0,0};
    getLocalMac(srcMac);
    const uint16_t seq = nextSeq_++;
    std::vector<uint8_t> plain;
    buildEnvelope(srcMac, expectedDstMac, seq, appPlain, plain);

    rc = encryptPayload(plain);
    if (rc != TCPMSG_OK) return rc;

    const uint16_t encLen = static_cast<uint16_t>(plain.size());
    std::vector<uint8_t> frame(4 + encLen);
    frame[0] = type;
    frame[1] = chan;
    frame[2] = encLen & 0xFF;
    frame[3] = encLen >> 8;
    memcpy(&frame[4], plain.data(), encLen);

    /* ---------- occupy single pending slot ------------------------- */
    if (xSemaphoreTake(sendMtx_, 0) == pdFALSE)          return TCPMSG_ERR_BUSY;
    if (sendBusy_) { xSemaphoreGive(sendMtx_); return TCPMSG_ERR_BUSY; }

    pending_.frame       = std::move(frame);
    pending_.to.port     = port;
    pending_.needResolve = needResolve;
    memcpy(pending_.expectedDstMac, expectedDstMac, sizeof(pending_.expectedDstMac));
    pending_.seq = seq;
    pending_.plainLen = static_cast<uint16_t>(appPlain.size());
    lastSendSeq_ = seq;
    lastSendFlags_ = 0;
    memset(lastAckMac_, 0, sizeof(lastAckMac_));

    if (needResolve) {
        pending_.to.host = hostStr ? String(hostStr) : String();
        pending_.to.ip   = IPAddress();          // will be filled by worker
    } else {
        pending_.to.host = "";
        pending_.to.ip   = ip;
    }

    sendBusy_ = true;
    xSemaphoreGive(sendMtx_);

    xTaskNotifyGive(sendWorker_);                // wake worker
    return TCPMSG_QUEUED;
}

void TCPMessenger::_sendWorkerThunk(void* arg)
{
    static_cast<TCPMessenger*>(arg)->sendWorkerLoop();
}

void TCPMessenger::sendWorkerLoop()
{
    for (;;)
    {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);   // wait work
        if (!taskRunning_) vTaskDelete(nullptr); // exit if task not running

        PendingSend job;
        {
            xSemaphoreTake(sendMtx_, portMAX_DELAY);
            if (!sendBusy_) { xSemaphoreGive(sendMtx_); continue; }
            job = pending_;        // copy
            xSemaphoreGive(sendMtx_);
        }

        /* ---- resolve if needed ------------------------------------ */
        if (job.needResolve) {
            if (!resolveHost(job.to.host.c_str(), job.to.ip)) {
                notifySendDone(TCPMSG_ERR_RESOLVE, job.to,
                               job.frame[0], job.frame[1], job.plainLen);
                clearPending();
                continue;
            }
        }

        /* ---- hand off to async TCP -------------------------------- */
        auto rc = sendFrame(job.to,
                            job.frame[0],           // type
                            job.frame[1],           // chan
                            &job.frame[4],
                            static_cast<uint16_t>(job.frame.size()-4));

        if (rc != TCPMSG_OK) {
            notifySendDone(rc, job.to, job.frame[0], job.frame[1], job.plainLen);
            clearPending();
        }
        /* success path: onOutbound* callback will clearPending() */
    }
}

void TCPMessenger::clearPending()
{
    xSemaphoreTake(sendMtx_, portMAX_DELAY);
    sendBusy_ = false;
    pending_  = PendingSend{};   // reset
    xSemaphoreGive(sendMtx_);
}



// ------------------------------------------------------------------
// Low-level outbound frame send (one-shot AsyncClient)
// ------------------------------------------------------------------
TCPMsgResult TCPMessenger::sendFrame(const TCPMsgRemoteInfo& to,
                                     uint8_t type, uint8_t chan,
                                     const uint8_t* encPayload,
                                     uint16_t encLen)
{
    AsyncClient* c = new AsyncClient();
    if (!c) return TCPMSG_ERR_TRANSPORT;
    c->setNoDelay(true);

    OutboundCtx* ctx = new OutboundCtx();
    if (!ctx) { delete c; return TCPMSG_ERR_TRANSPORT; }
    ctx->client = c; ctx->to = to; ctx->type = type;
    ctx->chan   = chan; ctx->encLen = encLen; ctx->self = this;
    ctx->plainLen = pending_.plainLen;
    ctx->seq = pending_.seq;

    ctx->frame.resize(4 + encLen);
    ctx->frame[0] = type;
    ctx->frame[1] = chan;
    ctx->frame[2] = encLen & 0xFF;
    ctx->frame[3] = encLen >> 8;
    if (encLen) memcpy(&ctx->frame[4], encPayload, encLen);

    c->onConnect(&_onOutboundConnect, ctx);
    c->onError(&_onOutboundError, ctx);
    c->onDisconnect(&_onOutboundDisconnect, ctx);

    if (!c->connect(to.ip, to.port)) {
        _onOutboundError(ctx, c, -1);
        return TCPMSG_ERR_TRANSPORT;
    }
    return TCPMSG_OK;
}


// ------------------------------------------------------------------
// Outbound callbacks (static forwarders)
// ------------------------------------------------------------------
void TCPMessenger::_onOutboundConnect(void* arg, AsyncClient* c) {
    OutboundCtx* ctx = reinterpret_cast<OutboundCtx*>(arg);
    if (ctx && ctx->self) ctx->self->onOutboundConnect(ctx, c);
}

void TCPMessenger::_onOutboundError(void* arg, AsyncClient* c, int8_t error) {
    OutboundCtx* ctx = reinterpret_cast<OutboundCtx*>(arg);
    if (ctx && ctx->self) ctx->self->onOutboundError(ctx, c, error);
}

void TCPMessenger::_onOutboundDisconnect(void* arg, AsyncClient* c) {
    OutboundCtx* ctx = reinterpret_cast<OutboundCtx*>(arg);
    if (ctx && ctx->self) ctx->self->onOutboundDisconnect(ctx, c);
}


// ------------------------------------------------------------------
// Outbound instance handlers
// ------------------------------------------------------------------
void TCPMessenger::onOutboundConnect(OutboundCtx* ctx, AsyncClient* c) {
    if (!ctx) return;
    size_t written = c->write(reinterpret_cast<const char*>(ctx->frame.data()),
                              ctx->frame.size());
    if (written != ctx->frame.size()) {
        onOutboundError(ctx, c, -2);
        return;
    }
    c->send();
    notifySendDone(TCPMSG_OK, ctx->to, ctx->type, ctx->chan,
                   ctx->plainLen);
    c->close(true);
    clearPending();
}


void TCPMessenger::onOutboundError(OutboundCtx* ctx, AsyncClient* c, int8_t /*error*/) {
    if (!ctx) return;
    notifySendDone(TCPMSG_ERR_WRITE, ctx->to, ctx->type, ctx->chan, 0);
    if (c) c->close(true);
    clearPending();
}

void TCPMessenger::onOutboundDisconnect(OutboundCtx* ctx, AsyncClient* c) {
    (void)c;
    if (ctx) {
        delete ctx->client;
        delete ctx;
    }
    clearPending(); 
}


// ------------------------------------------------------------------
// Notify app about send completion
// plainLen = encryptedLen minus CRC (if encryption used)
// ------------------------------------------------------------------
void TCPMessenger::notifySendDone(TCPMsgResult rc, const TCPMsgRemoteInfo& to,
                                  uint8_t type, uint8_t chanId,
                                  uint16_t encLenMinusMaybe)
{
    lastSendOk_ = (rc == TCPMSG_OK);
    if (!sendDoneCB_) return;
    uint16_t plain = encLenMinusMaybe;
    if (enc_ && encLenMinusMaybe >= EncryptionHandler::CHECKSUM_SIZE)
        plain = encLenMinusMaybe - EncryptionHandler::CHECKSUM_SIZE;
    sendDoneCB_(rc, to, type, chanId, plain);
}



// ------------------------------------------------------------------
// Manual loop (currently no-op for pure AsyncTCP usage)
// ------------------------------------------------------------------
void TCPMessenger::loop() {
    // nothing needed; AsyncTCP runs via LWIP callbacks
}

void TCPMessenger::_rxWorkerThunk(void* arg) {
    static_cast<TCPMessenger*>(arg)->rxWorkerLoop();
}

void TCPMessenger::rxWorkerLoop() {
    for (;;) {

        RecvItem* it = nullptr;
        if (xQueueReceive(rxQueue_, &it, portMAX_DELAY) != pdTRUE) continue;
        if (it == nullptr) break;                 // graceful stop
        
        const uint8_t* cbPtr = nullptr;
        uint16_t       cbLen = 0;
        std::vector<uint8_t> decrypted; // local, freed on scope exit

        if (it->isEncrypted) {
            if (it->len) {
                std::vector<uint8_t> encVec(it->data, it->data + it->len);
                if (enc_ && enc_->decrypt(encVec, decrypted)) {
                    cbPtr = decrypted.data();
                    cbLen = static_cast<uint16_t>(decrypted.size());
                } else {
                    // decode error -> deliver empty payload per current behavior
                    cbPtr = nullptr;
                    cbLen = 0;
                }
            } else {
                cbPtr = nullptr; cbLen = 0;
            }
        } else {
            cbPtr = it->data;
            cbLen = it->len;
        }

        // Invoke user callback in app context
        if (recvCB_) {
            // Clamp to cap (defensive)
            if (cbLen > TCPMSG_MAX_PAYLOAD_ENCRYPTED) cbLen = TCPMSG_MAX_PAYLOAD_ENCRYPTED;
            if (it->from.host.isEmpty()) {
                String host;
                if (mdnsSniffer_.resolve(it->from.ip, host))
                    it->from.host = host;               // success
                //else
                    //gLogger->println("TCPMessenger: RX host resolve failed for " +
                    //                 it->from.ip.toString());
            }
            recvCB_(it->from, it->type, it->chan, cbPtr, cbLen);
        }

        if (it->data) vPortFree(it->data);
        delete it;
    }
    vTaskDelete(nullptr);
}


// ------------------------------------ examples

/*
TempMsg temp;
temp.setCelsius(23.4f);
gMessenger.sendToHost(temp, 0, "deviceB.local", 9000);

LogMsg log("Boot complete");
gMessenger.sendToIP(log, 0, peerIP, 9000);

gMessenger.onReceive([](const TCPMsgRemoteInfo& from,
                        uint8_t type,
                        uint8_t chan,
                        const uint8_t* payload,
                        uint16_t len){
    if (type == TempMsg::TYPE_ID) {
        tempSlots[chan].fromBuffer(payload, len);
        Serial.printf("Temp chan %u from %s = %.2f\n", chan,
                      from.ip.toString().c_str(), tempSlots[chan].valueC());
    } else if (type == LogMsg::TYPE_ID && chan == TCPMSG_ID_BROADCAST) {
        LogMsg log;
        if (log.fromBuffer(payload,len)) {
            Serial.printf("LOG from %s: %s\n", from.ip.toString().c_str(), log.text().c_str());
        }
    }
});
*/
