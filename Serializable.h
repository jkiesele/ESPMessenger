#pragma once

#include <cstdint>

namespace tcpmsg {

/**
 * @brief Base interface for application-level message payloads that can be sent
 *        through TCPMessenger.
 *
 * Role in the stack:
 * - This is the user-facing serialization interface at the top of the messaging stack.
 * - User-defined message types inherit from Serializable.
 * - TCPMessenger uses this interface to convert typed objects into a compact binary
 *   payload before encryption and transport.
 * - On the receive side, user code can reconstruct an object from the plaintext
 *   payload returned by TCPMessenger by calling fromBuffer(...).
 *
 * Serialization model:
 * - Objects are serialized only as their payload bytes.
 * - Transport metadata such as source/destination addresses, transport sequence
 *   numbers, retries, acknowledgements, and framing are handled in lower layers.
 * - Messenger-level metadata such as type and channel are handled by TCPMessenger.
 *
 * Intended usage pattern:
 * - Derive a message class from Serializable.
 * - Implement typeId(), payloadSize(), serializeTo(...), and fromBuffer(...).
 * - Send an instance through TCPMessenger::sendToIP(...).
 * - Receive a TCPMessenger::ReceivedMessage and reconstruct the object by calling
 *   fromBuffer(...) on the returned plaintext payload.
 *
 * Threading / ownership:
 * - Serializable itself does not own any transport resources.
 * - TCPMessenger treats Serializable objects as read-only during sending.
 * - Implementations should assume serializeTo(...) may be called from a send worker
 *   thread owned by TCPMessenger.
 *
 * Design notes:
 * - typeId() defines the application-level message type used by TCPMessenger.
 * - payloadSize() must match the exact number of bytes written by serializeTo(...).
 * - fromBuffer(...) should validate the input carefully and reject malformed or
 *   inconsistent payloads by returning false.
 *
 * Non-goals:
 * - This interface does not define encryption.
 * - It does not define transport framing.
 * - It does not define version negotiation or schema evolution by itself.
 */
class Serializable {
public:
    virtual ~Serializable() = default;

    /**
     * @brief Return the application-level type identifier for this message.
     *
     * This type identifier is included in the messenger-level header and is used by
     * the receiver to distinguish different payload formats.
     *
     * Contract:
     * - The returned value should be stable for a given message type.
     * - Different message classes should not intentionally reuse the same type ID
     *   unless they are wire-compatible by design.
     */
    virtual uint8_t typeId() const = 0;

    /**
     * @brief Return the exact serialized payload size in bytes.
     *
     * This is the size of the plaintext application payload only.
     * It does not include:
     * - messenger header bytes
     * - transport framing bytes
     * - encryption overhead added by lower layers
     *
     * Contract:
     * - Must exactly match the number of bytes written by serializeTo(...).
     * - Must be deterministic for the current object state.
     */
    virtual uint16_t payloadSize() const = 0;

    /**
     * @brief Serialize the object payload into the provided output buffer.
     *
     * @param dst Pointer to an output buffer of at least payloadSize() bytes.
     *
     * Contract:
     * - Must write exactly payloadSize() bytes.
     * - Must not write beyond that range.
     * - Must not assume any additional framing or metadata space before or after dst.
     *
     * Notes:
     * - TCPMessenger calls this during outbound message construction.
     * - Implementations should not perform hidden dynamic resizing of the buffer;
     *   the output size is determined by payloadSize().
     */
    virtual void serializeTo(uint8_t* dst) const = 0;

    /**
     * @brief Reconstruct object state from a plaintext payload buffer.
     *
     * @param src Pointer to the plaintext payload bytes.
     * @param len Number of bytes available in src.
     *
     * @return true if parsing succeeded and the object state is valid, false otherwise.
     *
     * Contract:
     * - Must validate the incoming payload length and internal consistency.
     * - Must return false for malformed, truncated, or incompatible payloads.
     * - On failure, the resulting object state should remain well-defined.
     *
     * Notes:
     * - This function operates on the plaintext payload returned by TCPMessenger.
     * - The caller is responsible for ensuring that the message type is the expected one.
     */
    virtual bool fromBuffer(const uint8_t* src, uint16_t len) = 0;
};

} // namespace tcpmsg