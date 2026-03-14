#pragma once


// linux
#include "PlatformNet.h"

namespace tcpmsg {

/**
 * @brief Low-level platform/socket helper functions for blocking TCP operations.
 *
 * Role in the overall stack:
 * - This is the lowest socket-facing layer in the current transport rewrite.
 * - It provides a minimal set of raw operations on connected TCP sockets.
 * - It is intentionally platform-dependent and may later differ between ESP32
 *   and Linux implementations.
 * - It does not know anything about transport framing, message formats,
 *   acknowledgements, retries, duplicate suppression, queues, or higher-level
 *   messenger semantics.
 *
 * Design intent:
 * - Keep this class as small and boring as possible.
 * - Restrict it to raw socket plumbing for already-connected sockets, plus
 *   outbound connect logic.
 * - Avoid leaking socket complexity upward any more than necessary.
 *
 * Typical users:
 * - SocketServer::Connection, which wraps accepted inbound sockets.
 * - A future outbound transaction helper, which needs blocking connect/write/read.
 *
 * Non-goals:
 * - No ownership of threads/tasks.
 * - No server/listener lifecycle.
 * - No protocol framing.
 * - No knowledge of MAC addresses, sequence numbers, or transport packets.
 */
class SocketUtils {
public:
    /**
     * @brief Sentinel value used to mark an invalid socket descriptor.
     *
     * A descriptor equal to kInvalidFd is considered closed/unusable.
     */
    static constexpr int kInvalidFd = -1;

    /**
     * @brief Open a TCP connection to a concrete IP/port with a bounded timeout.
     *
     * Expected behavior:
     * - Creates a socket.
     * - Initiates a TCP connection to the given remote address.
     * - Waits until the socket becomes writable or the timeout expires.
     * - On success, restores blocking mode and applies send/receive timeouts.
     *
     * Why this exists:
     * - Outbound transport logic should not need to deal with non-blocking
     *   connect mechanics, select(), or socket option details directly.
     *
     * @param ip Remote IPv4 address.
     * @param port Remote TCP port.
     * @param timeoutMs Timeout in milliseconds for connection establishment.
     *
     * @return A valid connected socket descriptor on success, or kInvalidFd on failure.
     *
     * Failure cases may include:
     * - socket creation failure
     * - connect failure
     * - timeout while connecting
     * - inability to restore desired socket state
     * - inability to apply send/receive timeouts
     *
     * Notes:
     * - The returned socket is intended for blocking use with bounded read/write
     *   timeouts.
     * - The function does not distinguish timeout vs other errors at the API level;
     *   callers only receive success/failure.
     */
    static int connectTo(const IPAddress& ip, uint16_t port, uint32_t timeoutMs);

    /**
     * @brief Read exactly @p len bytes from a connected socket.
     *
     * Expected behavior:
     * - Repeatedly calls recv() until either:
     *   - exactly len bytes have been read, or
     *   - an error/timeout/disconnect occurs.
     *
     * @param fd Connected socket descriptor.
     * @param dst Destination buffer. Must be non-null if len > 0.
     * @param len Number of bytes to read.
     * @param timeoutMs Read timeout in milliseconds.
     *
     * @return true if exactly len bytes were read, false otherwise.
     *
     * Returns false if:
     * - fd is invalid
     * - dst is null while len > 0
     * - timeout occurs before all bytes are received
     * - peer disconnects
     * - recv() reports an unrecoverable error
     *
     * Notes:
     * - This function is intentionally strict: partial reads are treated as
     *   incomplete until the full requested length has arrived.
     * - This is useful for fixed-size protocol fields and framing headers.
     */
    static bool readExact(int fd, uint8_t* dst, size_t len, uint32_t timeoutMs);

    /**
     * @brief Write exactly @p len bytes to a connected socket.
     *
     * Expected behavior:
     * - Repeatedly calls send() until either:
     *   - exactly len bytes have been written, or
     *   - an error/timeout occurs.
     *
     * @param fd Connected socket descriptor.
     * @param src Source buffer. Must be non-null if len > 0.
     * @param len Number of bytes to write.
     * @param timeoutMs Write timeout in milliseconds.
     *
     * @return true if exactly len bytes were written, false otherwise.
     *
     * Returns false if:
     * - fd is invalid
     * - src is null while len > 0
     * - timeout occurs before all bytes are sent
     * - send() reports an unrecoverable error
     *
     * Notes:
     * - This function hides partial-write handling from callers.
     * - This is particularly useful for complete protocol frames that must be
     *   transmitted in full before the next protocol step starts.
     */
    static bool writeExact(int fd, const uint8_t* src, size_t len, uint32_t timeoutMs);

    /**
     * @brief Apply a receive timeout to a socket.
     *
     * @param fd Socket descriptor.
     * @param timeoutMs Timeout in milliseconds.
     *
     * @return true on success, false on failure.
     *
     * Notes:
     * - This affects blocking recv() calls on the socket.
     * - It is mainly a low-level helper used by connect/read paths.
     */
    static bool setRecvTimeout(int fd, uint32_t timeoutMs);

    /**
     * @brief Apply a send timeout to a socket.
     *
     * @param fd Socket descriptor.
     * @param timeoutMs Timeout in milliseconds.
     *
     * @return true on success, false on failure.
     *
     * Notes:
     * - This affects blocking send() calls on the socket.
     * - It is mainly a low-level helper used by connect/write paths.
     */
    static bool setSendTimeout(int fd, uint32_t timeoutMs);

    /**
     * @brief Close a socket and invalidate the descriptor.
     *
     * Expected behavior:
     * - If fd is valid, attempts shutdown/close.
     * - Sets fd to kInvalidFd afterwards.
     *
     * @param fd Reference to the socket descriptor to close.
     *
     * Notes:
     * - Passing by reference avoids stale-descriptor bugs in callers.
     * - Safe to call repeatedly; closing an already-invalid descriptor is a no-op.
     */
    static void closeSocket(int& fd);

private:
    /**
     * @brief Wait until a socket becomes writable within the given timeout.
     *
     * Intended use:
     * - Internal helper for bounded non-blocking connect completion.
     *
     * @param fd Socket descriptor.
     * @param timeoutMs Timeout in milliseconds.
     *
     * @return true if the socket becomes writable and no pending socket error
     *         is reported, false otherwise.
     *
     * Notes:
     * - This is intentionally private because it exposes a low-level readiness
     *   concept that higher layers should not depend on directly.
     */
    static bool waitUntilWritable(int fd, uint32_t timeoutMs);
};

} // namespace tcpmsg
