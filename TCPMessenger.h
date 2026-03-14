#pragma once

#include <cstdint>
#include <vector>

#include "PlatformNet.h"
#include "PlatformThreads.h"
#include "PlatformMutex.h"
#include "TCPTransport.h"
#include "EncryptionHandler.h"
#include "Serializable.h"

namespace tcpmsg {

/**
 * @brief User-facing message layer built on top of TCPTransport.
 *
 * Role in the stack:
 * - TCPMessenger is the main application-facing networking class.
 * - It sits above TCPTransport and adds:
 *   - messenger-level header handling (type, channel, payload length)
 *   - serialization through Serializable
 *   - encryption/decryption through EncryptionHandler
 *   - asynchronous send execution with retries
 * - It deliberately does not perform hostname/mDNS resolution or higher-level
 *   application dispatch logic.
 *
 * High-level wire format handled by this layer:
 * +--------+--------+--------+--------+----------------------+
 * | Type   | ChanId | LenLo  | LenHi  | EncryptedPayload[n]  |
 * +--------+--------+--------+--------+----------------------+
 *    1 B      1 B      1 B      1 B            n bytes
 *
 * Layer boundaries:
 * - TCPTransport handles only opaque payload transport, transport metadata,
 *   acknowledgements, duplicate suppression, and receive threading.
 * - TCPMessenger handles messenger-level payload semantics, serialization, and
 *   encryption.
 * - User code handles application-level interpretation of received messages.
 *
 * Threading model:
 * - TCPTransport owns an internal receive thread that fills its transport RX queue.
 * - TCPMessenger owns an internal send worker thread.
 * - Outbound sends are queued into a single pending send slot and executed
 *   asynchronously by the worker thread.
 * - Received messages are not queued again at the messenger layer; instead,
 *   popReceivedMessage(...) pulls one raw transport message from TCPTransport,
 *   validates and decrypts it, and returns the plaintext payload to the caller.
 *
 * Send semantics:
 * - sendToIP(...) validates and prepares a messenger payload immediately.
 * - If accepted, the request is stored in a single pending slot and the function
 *   returns quickly.
 * - The send worker then performs the actual blocking transport send, including
 *   optional retry attempts.
 * - The final result can later be retrieved via popSendResult(...).
 *
 * Receive semantics:
 * - popReceivedMessage(...) is polling-style.
 * - On success, it returns one fully validated and decrypted plaintext message.
 * - The caller is then responsible for:
 *   - checking type and channel if needed
 *   - constructing or updating a Serializable object using fromBuffer(...)
 *
 * Ownership / lifetime:
 * - TCPMessenger does not own the EncryptionHandler object; it stores only a pointer.
 * - The EncryptionHandler passed to begin(...) must remain valid for as long as the
 *   messenger is running.
 *
 * Non-goals:
 * - No automatic mDNS or hostname resolution.
 * - No application-level callback dispatch.
 * - No second receive queue above TCPTransport.
 * - No automatic deserialization into user objects.
 */
class TCPMessenger {
public:
    /**
     * @brief Result codes for messenger-level operations.
     *
     * Notes:
     * - Ok means success.
     * - NoMessage means that no valid received message was currently available.
     * - RetryLimitReached means a queued send was attempted repeatedly and still
     *   failed with a retryable transport error.
     * - InvalidEnvelope and DecryptFailed refer to received messages that were
     *   transported successfully but could not be interpreted at messenger level.
     */
    enum class Result : uint8_t {
        Ok = 0,
        NoMessage,
        NotRunning,
        Busy,
        InvalidArgument,
        TooLarge,
        SerializeFailed,
        EncryptFailed,
        DecryptFailed,
        InvalidEnvelope,
        TransportError,
        RetryLimitReached
    };

    /**
     * @brief Options controlling asynchronous send behavior.
     *
     * timeoutMs:
     * - Timeout used for one underlying transport send attempt.
     *
     * maxRetries:
     * - Number of additional retry attempts after the first try.
     * - Example: maxRetries = 3 means up to 4 total attempts.
     *
     * retryDelayMs:
     * - Delay inserted between retry attempts.
     */
    struct SendOptions {
        uint32_t timeoutMs = 1000;
        uint8_t maxRetries = 3;
        uint32_t retryDelayMs = 0;
    };

    /**
     * @brief Result mailbox entry returned by popSendResult(...).
     *
     * rc:
     * - Final messenger-level result of the queued send.
     *
     * ip / port:
     * - Destination that was used for that send.
     */
    struct SendResult {
        Result rc = Result::TransportError;
        IPAddress ip;
        uint16_t port = 0;
    };

    /**
     * @brief One successfully received and decoded messenger-level message.
     *
     * peerIp / peerPort:
     * - Socket-level peer address metadata of the transport sender.
     *
     * srcMac / dstMac / seq:
     * - Transport-level metadata carried up from TCPTransport.
     *
     * type / chanId:
     * - Messenger-level header fields.
     *
     * payload:
     * - Decrypted plaintext payload bytes.
     * - These bytes can be passed to Serializable::fromBuffer(...).
     */
    struct ReceivedMessage {
        IPAddress peerIp;
        uint16_t peerPort = 0;

        MACAddress srcMac;
        MACAddress dstMac;
        uint16_t seq = 0;

        uint8_t type = 0;
        uint8_t chanId = 0;

        std::vector<uint8_t> payload;
    };

    TCPMessenger() = default;
    ~TCPMessenger();

    TCPMessenger(const TCPMessenger&) = delete;
    TCPMessenger& operator=(const TCPMessenger&) = delete;

    /**
     * @brief Start the messenger and the underlying transport.
     *
     * @param listenPort Local TCP port on which the underlying transport listens.
     * @param localMac Local logical MAC address used by the transport layer.
     * @param encryptionHandler Pointer to the encryption helper used for outbound
     *        encryption and inbound decryption.
     *
     * @return true on success, false on failure.
     *
     * Contract:
     * - encryptionHandler must remain valid until end() has completed.
     * - Calling begin() on an already running object resets and restarts it.
     */
    bool begin(uint16_t listenPort,
               const MACAddress& localMac,
               EncryptionHandler* encryptionHandler);

    /**
     * @brief Stop the messenger, stop the send worker, and stop the transport.
     *
     * Notes:
     * - After end(), the object is no longer running.
     * - Pending sends are cancelled as part of shutdown.
     * - Safe to call repeatedly.
     */
    void end();

    /**
     * @brief Check whether the messenger is currently running.
     *
     * @return true if begin() succeeded and end() has not completed since.
     */
    bool isRunning() const;

    /**
     * @brief Queue one application object for asynchronous sending to a concrete IP/port.
     *
     * Steps performed by this call:
     * - validate arguments
     * - serialize the object payload using Serializable
     * - encrypt the plaintext payload using EncryptionHandler
     * - build the messenger-level envelope
     * - store the resulting transport payload in the single pending send slot
     *
     * The actual transport send happens later in the internal send worker thread.
     *
     * @param obj Application object to serialize and send.
     * @param chanId Messenger-level channel identifier.
     * @param ip Destination IP address.
     * @param port Destination TCP port.
     * @param expectedDstMac Expected transport destination MAC used by TCPTransport.
     * @param options Send timing and retry options.
     *
     * @return
     * - Ok if the send request was accepted into the pending slot
     * - Busy if another send is already pending
     * - NotRunning if the messenger is not running
     * - TooLarge if the final messenger payload cannot fit into the transport payload limit
     * - InvalidArgument for invalid parameters
     *
     * Notes:
     * - The application-level type field is inferred from obj.typeId().
     * - Final success or failure is reported later via popSendResult(...).
     */
    Result sendToIP(const Serializable& obj,
                    uint8_t chanId,
                    const IPAddress& ip,
                    uint16_t port,
                    const MACAddress& expectedDstMac);

    /**
     * @brief Queue one application object for asynchronous sending with explicit send options.
     *
     * Same semantics as the shorter overload, but with caller-provided timeout/retry settings.
     */
    Result sendToIP(const Serializable& obj,
                    uint8_t chanId,
                    const IPAddress& ip,
                    uint16_t port,
                    const MACAddress& expectedDstMac,
                    const SendOptions& options);

    /**
     * @brief Pop the final result of the most recently completed queued send.
     *
     * @param out Destination result structure.
     *
     * @return true if a result was available and written to out, false otherwise.
     *
     * Notes:
     * - This is a polling mailbox, not a queue.
     * - If no completed send result is currently available, the function returns false.
     */
    bool popSendResult(SendResult& out);

    /**
     * @brief Poll for one fully validated and decrypted incoming messenger message.
     *
     * @param out Receives the decoded message on success.
     * @param rc Receives the status of the attempt.
     *
     * @return true if a valid message was returned in out, false otherwise.
     *
     * Semantics:
     * - true:
     *   - out contains one valid received message
     *   - rc == Result::Ok
     * - false:
     *   - no valid message was returned
     *   - rc explains why, for example:
     *     - NoMessage
     *     - NotRunning
     *     - InvalidEnvelope
     *     - DecryptFailed
     *
     * Notes:
     * - This function consumes at most one transport message per call.
     * - It performs messenger header parsing and decryption before returning.
     * - It does not deserialize into a Serializable object automatically.
     */
    bool popReceivedMessage(ReceivedMessage& out, Result& rc);

private:
    struct PendingSend {
        IPAddress ip;
        uint16_t port = 0;
        MACAddress expectedDstMac;

        std::vector<uint8_t> transportPayload;
        SendOptions options;
    };

    static void sendThreadMain(void* ctx);
    void sendLoop();

    Result buildOutgoingTransportPayload(const Serializable& obj,
                                         uint8_t chanId,
                                         std::vector<uint8_t>& outTransportPayload);

    Result decodeIncomingTransportMessage(const TCPTransport::Message& in,
                                          ReceivedMessage& out);

    static bool isRetryable(TCPTransport::Result rc);
    static Result mapTransportResult(TCPTransport::Result rc, bool retriesExhausted);

private:
    static constexpr uint32_t kTxPollSleepMs = 10;

    mutable PlatformMutex mutex_;

    TCPTransport transport_;
    EncryptionHandler* encryptionHandler_ = nullptr;

    PlatformThread sendThread_;

    bool running_ = false;
    bool sendPending_ = false;

    PendingSend pendingSend_;
    bool sendResultReady_ = false;
    SendResult sendResult_;
};

} // namespace tcpmsg