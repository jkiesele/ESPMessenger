#pragma once

#include <cstdint>
#include <vector>
#include <cstdlib> // for rand()

namespace tcpmsg {

class CRC32 {
public:
    static uint32_t calculate(const uint8_t* data, size_t length);
};


/**
 * @brief Small helper for payload encryption and decryption used by TCPMessenger.
 *
 * Role in stack:
 * - Used only at messenger level.
 * - TCPTransport never sees plaintext semantics or encryption details.
 * - TCPMessenger encrypts serialized payload bytes before sending and decrypts
 *   received messenger payload bytes before returning them to user code.
 *
 * Intended use:
 * - Construct one EncryptionHandler with a shared key set.
 * - Pass it to TCPMessenger::begin(...).
 * - Keep it alive for as long as the messenger is running.
 *
 * Design notes:
 * - This class is intentionally small and self-contained.
 * - It operates only on byte buffers.
 * - It does not know anything about Serializable, channels, transport ACKs,
 *   sockets, or framing.
 *
 * Threading:
 * - TCPMessenger may call encrypt(...) and decrypt(...) from different internal
 *   code paths.
 * - The implementation should therefore either be effectively read-only after
 *   construction or otherwise safe for that usage pattern.
 */
class EncryptionHandler {
public:
    static constexpr size_t CHECKSUM_SIZE = 4;

    /**
     * @brief Construct an encryption helper from a set of keys.
     *
     * @param keys Pointer or reference to the configured encryption keys.
     *
     * Contract:
     * - The provided key material must remain valid for as long as the handler
     *   depends on it, unless the implementation explicitly copies it internally.
     */
    explicit EncryptionHandler(const std::vector<uint32_t>* keys);

    /**
     * @brief Encrypt a plaintext payload buffer.
     *
     * @param plaintext Plain application payload bytes.
     *
     * @return Encrypted payload bytes suitable for insertion into the
     *         messenger-level payload field.
     *
     * Notes:
     * - The returned data is payload-only.
     * - Messenger header and transport framing are handled elsewhere.
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) const;

    /**
     * @brief Decrypt an encrypted payload buffer.
     *
     * @param encrypted Encrypted payload bytes from the messenger-level payload field.
     * @param plaintext Output buffer receiving the decrypted plaintext bytes.
     *
     * @return true if decryption and validation succeeded, false otherwise.
     *
     * Notes:
     * - Implementations should reject malformed or invalid encrypted payloads
     *   by returning false.
     * - On failure, callers should treat the corresponding received message as
     *   invalid at messenger level.
     */
    bool decrypt(const std::vector<uint8_t>& encrypted,
                 std::vector<uint8_t>& plaintext) const;

private:
    void randomizeKeyIndex() const {
        keyIndex_ = rand() % encryptionKeys_->size();
    }
    mutable size_t keyIndex_;
    const std::vector<uint32_t> * encryptionKeys_;
};

} // namespace tcpmsg
