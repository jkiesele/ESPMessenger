#ifndef SERIALIZABLE_H
#define SERIALIZABLE_H

#include <Arduino.h>
#include <stdint.h>
#include <PacketIO.h>

/**
 * @brief Base for all small binary messages (<256 B encrypted).
 *
 * Implementors must provide:
 *   - typeId()        : 1-byte application type tag (0–255).
 *   - payloadSize()   : number of plaintext payload bytes when serialized (<=251 if encrypted).
 *   - serializeTo()   : write exactly payloadSize() bytes to dst.
 *   - fromBuffer()    : parse (len) bytes and update *this* in place; return true if valid.
 *
 * Wire format (as sent by TCPMessenger):
 *
 *   +-------+----------+-------------------------+
 *   | Type  | LenEnc   |   EncryptedPayload[n]   |
 *   +-------+----------+-------------------------+
 *     1 B      1 B           n bytes
 *
 * - Type: your typeId().
 * - LenEnc: number of bytes following (encrypted payload length).
 * - EncryptedPayload: if EncryptionHandler provided, this is the encrypted+CRC blob;
 *   otherwise it is the raw plaintext payload.
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