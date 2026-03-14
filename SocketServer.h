#pragma once

#include "PlatformNet.h" // double but just to be safe against changes in SocketUtils.h
#include "SocketUtils.h"

namespace tcpmsg {

/**
 * @brief Blocking TCP listener abstraction built on top of SocketUtils.
 *
 * Role in the overall stack:
 * - This is the last platform-dependent socket layer intended to be visible
 *   to the rest of the transport implementation.
 * - It wraps the lifecycle of a listening TCP socket and accepted inbound
 *   client connections.
 * - Everything above this class should ideally stop dealing with raw socket
 *   descriptors, lwIP details, select(), sockaddr, and similar platform details.
 *
 * Design intent:
 * - Provide a small, explicit server abstraction for inbound TCP connections.
 * - Keep the API blocking and simple.
 * - Expose accepted clients as RAII-owned Connection objects rather than raw fds.
 *
 * Relationship to SocketUtils:
 * - SocketUtils remains the raw socket helper layer.
 * - SocketServer is the first abstraction layer above that raw helper layer.
 * - Connection delegates connected-socket read/write/close operations to
 *   SocketUtils.
 *
 * Non-goals:
 * - No transport framing.
 * - No protocol parsing.
 * - No mailbox/queue handling.
 * - No knowledge of ACKs, sequence numbers, MAC addresses, or message semantics.
 * - No task/thread ownership at this stage.
 */
class SocketServer {
public:
    /**
     * @brief RAII wrapper for one accepted inbound TCP connection.
     *
     * Purpose:
     * - Represents a single connected client socket accepted by SocketServer.
     * - Hides the raw socket descriptor from higher layers.
     * - Provides simple blocking exact-read / exact-write operations.
     *
     * Ownership model:
     * - Move-only.
     * - Non-copyable to avoid accidental descriptor aliasing.
     * - Automatically closes the socket on destruction.
     *
     * Typical use:
     * - Accept a connection from SocketServer.
     * - Check isValid().
     * - Read/write protocol bytes.
     * - Let destruction or close() release the socket.
     */
    class Connection {
    public:
        /**
         * @brief Construct an invalid/empty connection.
         *
         * An object created this way does not own a connected socket.
         * It becomes usable only if it is move-assigned from a valid accepted
         * connection, or internally constructed by SocketServer.
         */
        Connection() = default;

        /**
         * @brief Destroy the connection and close the socket if still open.
         */
        ~Connection();

        Connection(const Connection&) = delete;
        Connection& operator=(const Connection&) = delete;

        /**
         * @brief Move-construct a connection, transferring socket ownership.
         *
         * After the move, the source object becomes invalid.
         */
        Connection(Connection&& other) noexcept;

        /**
         * @brief Move-assign a connection, transferring socket ownership.
         *
         * Existing owned socket state, if any, is released before taking over
         * the source socket. The source becomes invalid afterwards.
         */
        Connection& operator=(Connection&& other) noexcept;

        /**
         * @brief Check whether this object currently owns a valid connected socket.
         *
         * @return true if the connection is usable, false otherwise.
         */
        bool isValid() const { return fd_ >= 0; }

        /**
         * @brief Read exactly @p len bytes from this connection.
         *
         * Delegates to SocketUtils::readExact().
         *
         * @param dst Destination buffer. Must be non-null if len > 0.
         * @param len Number of bytes to read.
         * @param timeoutMs Timeout in milliseconds.
         *
         * @return true if exactly len bytes were read, false otherwise.
         *
         * Returns false if:
         * - the connection is invalid
         * - the peer disconnects early
         * - a timeout occurs
         * - a socket error occurs
         */
        bool readExact(uint8_t* dst, size_t len, uint32_t timeoutMs);

        /**
         * @brief Write exactly @p len bytes to this connection.
         *
         * Delegates to SocketUtils::writeExact().
         *
         * @param src Source buffer. Must be non-null if len > 0.
         * @param len Number of bytes to write.
         * @param timeoutMs Timeout in milliseconds.
         *
         * @return true if exactly len bytes were written, false otherwise.
         *
         * Returns false if:
         * - the connection is invalid
         * - a timeout occurs
         * - a socket error occurs
         */
        bool writeExact(const uint8_t* src, size_t len, uint32_t timeoutMs);


        const IPAddress& peerIP() const { return peerIp_; }
        uint16_t peerPort() const { return peerPort_; }

        /**
         * @brief Close the connection and invalidate this object.
         *
         * Safe to call repeatedly.
         */
        void close();

    private:
        friend class SocketServer;

        /**
         * @brief Construct a valid connection from an accepted socket descriptor.
         *
         * This constructor is intentionally private; only SocketServer may create
         * valid accepted connections.
         */
        Connection(int fd, const IPAddress& peerIp, uint16_t peerPort)
             : fd_(fd), peerIp_(peerIp), peerPort_(peerPort) {}

        /**
         * @brief Owned connected socket descriptor, or SocketUtils::kInvalidFd.
         */
        int fd_ = SocketUtils::kInvalidFd;
        IPAddress peerIp_{};
        uint16_t peerPort_ = 0;
    };

    /**
     * @brief Construct an inactive server.
     *
     * No listening socket is created until begin() succeeds.
     */
    SocketServer() = default;

    /**
     * @brief Destroy the server and close the listening socket if active.
     */
    ~SocketServer();

    SocketServer(const SocketServer&) = delete;
    SocketServer& operator=(const SocketServer&) = delete;

    /**
     * @brief Create, bind, and start a listening TCP socket.
     *
     * Expected behavior:
     * - Creates a listening socket bound to the given local port.
     * - Starts listening with the specified backlog.
     * - Replaces any previously running listener owned by this object.
     *
     * @param port Local TCP port to listen on.
     * @param backlog Maximum pending connection backlog passed to listen().
     *
     * @return true on success, false on failure.
     *
     * Failure cases may include:
     * - socket creation failure
     * - bind failure
     * - listen failure
     *
     * Notes:
     * - On failure, the server remains not running.
     * - Calling begin() again should reset prior listener state first.
     */
    bool begin(uint16_t port, int backlog = 4);

    /**
     * @brief Stop listening and close the listening socket.
     *
     * Notes:
     * - This affects only the listening socket owned by SocketServer itself.
     * - Already accepted Connection objects remain independent and manage their
     *   own connected sockets separately.
     * - Safe to call repeatedly.
     */
    void end();

    /**
     * @brief Check whether the server currently owns an active listening socket.
     *
     * @return true if begin() succeeded and end() has not been called since.
     */
    bool isRunning() const { return listenFd_ >= 0; }

    /**
     * @brief Wait for and accept one inbound client connection.
     *
     * Expected behavior:
     * - Waits up to timeoutMs for the listening socket to become readable.
     * - Accepts one pending client if available.
     * - Applies read/write timeouts to the accepted socket.
     * - Returns a Connection object owning that accepted socket.
     *
     * @param timeoutMs Maximum time to wait for a connection, in milliseconds.
     *
     * @return A valid Connection on success, or an invalid Connection on timeout
     *         or error.
     *
     * Notes:
     * - Timeout and accept errors are intentionally collapsed into the same
     *   "invalid connection" result at this abstraction level.
     * - Higher layers that need more detailed diagnostics can be extended later,
     *   but the current design keeps this interface intentionally simple.
     */
    Connection accept(uint32_t timeoutMs);

private:
    /**
     * @brief Wait until the listening socket becomes readable.
     *
     * Intended use:
     * - Internal helper before calling accept().
     *
     * @param fd Listening socket descriptor.
     * @param timeoutMs Timeout in milliseconds.
     *
     * @return true if the socket becomes readable within the timeout, false otherwise.
     */
    static bool waitUntilReadable(int fd, uint32_t timeoutMs);

    /**
     * @brief Owned listening socket descriptor, or SocketUtils::kInvalidFd.
     */
    int listenFd_ = SocketUtils::kInvalidFd;
};

} // namespace tcpmsg