#ifndef TCP_MESSAGE_H
#define TCP_MESSAGE_H

#include <Arduino.h>
#include <stdint.h>
#include <utility>

#include "Serializable.h"
#include "Helpers.h"   // for TCPMsgRemoteInfo / MACAddress

class Message {
public:
    Message() = default;

    ~Message() {
        clear();
    }

    Message(const Message&) = delete;
    Message& operator=(const Message&) = delete;

    Message(Message&& other) noexcept {
        moveFrom(std::move(other));
    }

    Message& operator=(Message&& other) noexcept {
        if (this != &other) {
            clear();
            moveFrom(std::move(other));
        }
        return *this;
    }

    bool valid() const {
        return payload_ != nullptr || payloadLen_ == 0;
    }

    bool hasPayload() const {
        return payload_ != nullptr && payloadLen_ > 0;
    }

    void clear() {
        if (payload_) {
            freePayload_(payload_);
            payload_ = nullptr;
        }
        payloadLen_ = 0;
        type_ = 0;
        chanId_ = 0;
        from_ = TCPMsgRemoteInfo{};
    }

    uint8_t type() const { return type_; }
    uint8_t channel() const { return chanId_; }
    uint16_t payloadSize() const { return payloadLen_; }

    const TCPMsgRemoteInfo& from() const { return from_; }

    const uint8_t* data() const { return payload_; }
    uint8_t* data() { return payload_; }

    bool toObject(Serializable& obj) const {
        if (obj.typeId() != type_) return false;
        return obj.fromBuffer(payload_, payloadLen_);
    }

    template <class T>
    bool toObject(T& obj) const {
        static_assert(std::is_base_of<Serializable, T>::value,
                      "T must derive from Serializable");
        if (obj.typeId() != type_) return false;
        return obj.fromBuffer(payload_, payloadLen_);
    }

    // For debugging / very low-level handling
    bool matchesType(uint8_t t) const {
        return type_ == t;
    }

private:
    friend class TCPMessenger;

    using FreePayloadFn = void (*)(uint8_t*);

    void adopt(const TCPMsgRemoteInfo& from,
               uint8_t type,
               uint8_t chanId,
               uint8_t* payload,
               uint16_t payloadLen,
               FreePayloadFn freeFn) {
        clear();
        from_ = from;
        type_ = type;
        chanId_ = chanId;
        payload_ = payload;
        payloadLen_ = payloadLen;
        freePayload_ = freeFn ? freeFn : &Message::defaultFree;
    }

    static void defaultFree(uint8_t* p) {
        if (p) {
            free(p);
        }
    }

    void moveFrom(Message&& other) noexcept {
        from_ = other.from_;
        type_ = other.type_;
        chanId_ = other.chanId_;
        payload_ = other.payload_;
        payloadLen_ = other.payloadLen_;
        freePayload_ = other.freePayload_;

        other.payload_ = nullptr;
        other.payloadLen_ = 0;
        other.type_ = 0;
        other.chanId_ = 0;
        other.from_ = TCPMsgRemoteInfo{};
        other.freePayload_ = &Message::defaultFree;
    }

    TCPMsgRemoteInfo from_{};
    uint8_t type_ = 0;
    uint8_t chanId_ = 0;

    uint8_t* payload_ = nullptr;
    uint16_t payloadLen_ = 0;

    FreePayloadFn freePayload_ = &Message::defaultFree;
};

#endif