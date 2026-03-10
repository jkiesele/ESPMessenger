#ifndef SERIALIZABLE_H
#define SERIALIZABLE_H


#include <stdint.h>
#include <PacketIO.h>

/**
 * @brief Base for binary messages carried by TCPMessenger.
 *
 * Implementors must provide:
 *   - typeId()        : 1-byte application type tag (0–255).
 *   - payloadSize()   : number of plaintext payload bytes when serialized (<=251 if encrypted).
 *   - serializeTo()   : write exactly payloadSize() bytes to dst.
 *   - fromBuffer()    : parse (len) bytes and update *this* in place; return true if valid.
 *
 * Wire format (as sent by TCPMessenger):
 *
 *   +-------+--------+--------+-------------------------+
 *   | Type  | ChanId  | LenLo  | LenHi  | EncryptedPayload[n] |
 *   +-------+--------+--------+--------+-------------------------+
 *      1 B      1 B      1 B      1 B            n bytes
 *
 * - Type: your typeId().
 * - ChanId: application-defined channel ID.
 * - LenLo/LenHi: encrypted payload length as little-endian uint16_t.
 * - EncryptedPayload: envelope + serialized application payload, optionally protected
 *   by EncryptionHandler.
 *
 * The transport-wide hard cap for the encrypted payload is TCPMSG_MAX_PAYLOAD_ENCRYPTED.
 */
class Serializable {
public:
    virtual ~Serializable() {}

    virtual uint8_t typeId() const = 0;

    //stay below TCPMessenger::TCPMSG_MAX_PAYLOAD_ENCRYPTED
    virtual uint16_t payloadSize() const = 0;

    virtual void serializeTo(uint8_t* dst) const = 0;
    virtual bool fromBuffer(const uint8_t* src, uint16_t len) = 0;
};

#endif // SERIALIZABLE_H