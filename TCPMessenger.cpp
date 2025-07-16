#include "TCPMessenger.h"
#include <cstring>        // memcpy
#include <LoggingBase.h>  // optional; provides gLogger?

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
}


TCPMessenger::~TCPMessenger() {
    endServer();
    if (_tcpMessengerSingleton == this) {
        _tcpMessengerSingleton = nullptr;
    }
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
// ------------------------------------------------------------------
void TCPMessenger::parseBytes(ClientCtx* ctx, const uint8_t* data, size_t len) {
    while (len--) {
        uint8_t b = *data++;

        if (!ctx->haveHeader) {
            // expecting type then length
            if (ctx->rxPos == 0) {
                ctx->rxType = b;
                ctx->rxPos = 1;
            } else {
                ctx->rxLenEnc   = b;
                ctx->haveHeader = true;
                ctx->rxPos      = 0;

                if (ctx->rxLenEnc > TCPMSG_MAX_PAYLOAD_ENCRYPTED) {
                    // protocol error: close connection
                    ctx->client->close(true);
                    return;
                }

                // zero-length payload? dispatch immediately
                if (ctx->rxLenEnc == 0) {
                    dispatchFrame(ctx->remote, ctx->rxType, nullptr, 0);
                    ctx->haveHeader = false;
                }
            }
            continue;
        }

        // collecting encrypted payload
        ctx->rxBuf[ctx->rxPos++] = b;
        if (ctx->rxPos >= ctx->rxLenEnc) {
            // full encrypted payload received -> dispatch
            dispatchFrame(ctx->remote,
                          ctx->rxType,
                          ctx->rxBuf,
                          ctx->rxLenEnc);

            // reset for next frame
            ctx->haveHeader = false;
            ctx->rxPos = 0;
        }
    }
}


// ------------------------------------------------------------------
// Dispatch a received frame (decrypt + user callback)
// ------------------------------------------------------------------
void TCPMessenger::dispatchFrame(const TCPMsgRemoteInfo& from,
                                 uint8_t type,
                                 const uint8_t* encPayload,
                                 uint8_t encLen)
{
    std::vector<uint8_t> decrypted;

    if (enc_) {
        // zero-length encrypted payload is not valid under current EncryptionHandler;
        // treat as decode error.
        if (encLen == 0) {
            if (recvCB_) recvCB_(from, type, nullptr, 0);
            return;
        }
        std::vector<uint8_t> encVec;
        encVec.reserve(encLen);
        if (encPayload && encLen) {
            encVec.insert(encVec.end(), encPayload, encPayload + encLen);
        }
        bool ok = enc_->decrypt(encVec, decrypted);
        if (!ok) {
            if (recvCB_) {
                recvCB_(from, type, nullptr, 0);  // signal decode error
            }
            return;
        }
    } else {
        // no encryption; payload is plaintext (can be zero-len)
        if (encPayload && encLen) {
            decrypted.assign(encPayload, encPayload + encLen);
        } else {
            decrypted.clear();
        }
    }

    if (recvCB_) {
        const uint8_t* ptr = decrypted.empty() ? nullptr : decrypted.data();
        uint8_t plen = static_cast<uint8_t>(decrypted.size());
        if (plen > TCPMSG_MAX_PAYLOAD_ENCRYPTED) {
            plen = TCPMSG_MAX_PAYLOAD_ENCRYPTED; // shouldn't happen
        }
        recvCB_(from, type, ptr, plen);
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
    uint8_t plainLen = msg.payloadSize();

    // Guard: after encryption must still fit in 1-byte length
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
// Public send: by hostname
// ------------------------------------------------------------------
TCPMsgResult TCPMessenger::sendToHost(const char* host,
                                      uint16_t port,
                                      const Serializable& msg)
{
    IPAddress ip;
    if (!resolveHost(host, ip)) {
        return TCPMSG_ERR_RESOLVE;
    }

    TCPMsgRemoteInfo to;
    to.ip = ip;
    to.port = port;
    to.host = host ? String(host) : String();

    // build plaintext & send
    std::vector<uint8_t> plain;
    uint8_t type = 0;
    TCPMsgResult rc = buildPlain(msg, plain, type);
    if (rc != TCPMSG_OK) return rc;

    rc = encryptPayload(plain);
    if (rc != TCPMSG_OK) return rc;

    return sendFrame(to, type, plain.data(), (uint8_t)plain.size());
}


// ------------------------------------------------------------------
// Public send: by IP
// ------------------------------------------------------------------
TCPMsgResult TCPMessenger::sendToIP(const IPAddress& ip,
                                    uint16_t port,
                                    const Serializable& msg)
{
    TCPMsgRemoteInfo to;
    to.ip = ip;
    to.port = port;
    to.host = ""; // unknown

    std::vector<uint8_t> plain;
    uint8_t type = 0;
    TCPMsgResult rc = buildPlain(msg, plain, type);
    if (rc != TCPMSG_OK) return rc;

    rc = encryptPayload(plain);
    if (rc != TCPMSG_OK) return rc;

    return sendFrame(to, type, plain.data(), (uint8_t)plain.size());
}


// ------------------------------------------------------------------
// Low-level outbound frame send (one-shot AsyncClient)
// ------------------------------------------------------------------
TCPMsgResult TCPMessenger::sendFrame(const TCPMsgRemoteInfo& to,
                                     uint8_t type,
                                     const uint8_t* encPayload,
                                     uint8_t encLen)
{
    AsyncClient* c = new AsyncClient();
    if (!c) return TCPMSG_ERR_TRANSPORT;

    // reduce latency
    c->setNoDelay(true);

    OutboundCtx* ctx = new OutboundCtx();
    if (!ctx) {
        delete c;
        return TCPMSG_ERR_TRANSPORT;
    }

    ctx->client = c;
    ctx->to = to;
    ctx->type = type;
    ctx->encLen = encLen;
    ctx->self = this;

    // build frame: header + payload
    ctx->frame.resize(2 + encLen);
    ctx->frame[0] = type;
    ctx->frame[1] = encLen;
    if (encLen) {
        memcpy(&ctx->frame[2], encPayload, encLen);
    }

    // attach outbound callbacks
    c->onConnect(&_onOutboundConnect, ctx);
    c->onError(&_onOutboundError, ctx);
    c->onDisconnect(&_onOutboundDisconnect, ctx);

    // attempt connect
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
    // write frame (cast to const char* for AsyncClient)
    size_t written = c->write(reinterpret_cast<const char*>(ctx->frame.data()),
                              ctx->frame.size());
    if (written != ctx->frame.size()) {
        onOutboundError(ctx, c, -2);
        return;
    }
    c->send();   // push to stack

    // For simplicity we treat 'send' as success (no remote ACK wait)
    notifySendDone(TCPMSG_OK, ctx->to, ctx->type,
                   ctx->encLen - (enc_ ? EncryptionHandler::CHECKSUM_SIZE : 0));

    c->close(true);  // done
}

void TCPMessenger::onOutboundError(OutboundCtx* ctx, AsyncClient* c, int8_t /*error*/) {
    if (!ctx) return;
    notifySendDone(TCPMSG_ERR_WRITE, ctx->to, ctx->type, 0);
    if (c) c->close(true);
}

void TCPMessenger::onOutboundDisconnect(OutboundCtx* ctx, AsyncClient* c) {
    (void)c;
    if (ctx) {
        delete ctx->client;
        delete ctx;
    }
}


// ------------------------------------------------------------------
// Notify app about send completion
// plainLen = encryptedLen minus CRC (if encryption used)
// ------------------------------------------------------------------
void TCPMessenger::notifySendDone(TCPMsgResult rc,
                                  const TCPMsgRemoteInfo& to,
                                  uint8_t type,
                                  uint8_t encLenMinusMaybe)
{
    if (sendDoneCB_) {
        uint8_t plainLen = encLenMinusMaybe;
        if (enc_ && encLenMinusMaybe >= EncryptionHandler::CHECKSUM_SIZE) {
            plainLen = encLenMinusMaybe - EncryptionHandler::CHECKSUM_SIZE;
        }
        sendDoneCB_(rc, to, type, plainLen);
    }
}


// ------------------------------------------------------------------
// Manual loop (currently no-op for pure AsyncTCP usage)
// ------------------------------------------------------------------
void TCPMessenger::loop() {
    // nothing needed; AsyncTCP runs via LWIP callbacks
}