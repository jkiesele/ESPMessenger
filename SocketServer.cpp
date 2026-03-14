#include "SocketServer.h"

namespace tcpmsg {

namespace {
timeval makeTimeval(uint32_t timeoutMs) {
    timeval tv{};
    tv.tv_sec  = static_cast<long>(timeoutMs / 1000UL);
    tv.tv_usec = static_cast<long>((timeoutMs % 1000UL) * 1000UL);
    return tv;
}
}

// ---------------- Connection ----------------

SocketServer::Connection::~Connection() {
    close();
}

SocketServer::Connection::Connection(Connection&& other) noexcept
    : fd_(other.fd_),
      peerIp_(other.peerIp_),
      peerPort_(other.peerPort_) {
    other.fd_ = SocketUtils::kInvalidFd;
    other.peerIp_ = IPAddress{};
    other.peerPort_ = 0;
}

SocketServer::Connection& SocketServer::Connection::operator=(Connection&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        peerIp_ = other.peerIp_;
        peerPort_ = other.peerPort_;
        other.fd_ = SocketUtils::kInvalidFd;
        other.peerIp_ = IPAddress{};
        other.peerPort_ = 0;
    }
    return *this;
}

bool SocketServer::Connection::readExact(uint8_t* dst, size_t len, uint32_t timeoutMs) {
    if (fd_ < 0) return false;
    return SocketUtils::readExact(fd_, dst, len, timeoutMs);
}

bool SocketServer::Connection::writeExact(const uint8_t* src, size_t len, uint32_t timeoutMs) {
    if (fd_ < 0) return false;
    return SocketUtils::writeExact(fd_, src, len, timeoutMs);
}

void SocketServer::Connection::close() {
    SocketUtils::closeSocket(fd_);
}

// ---------------- SocketServer ----------------

SocketServer::~SocketServer() {
    end();
}

bool SocketServer::begin(uint16_t port, int backlog) {
    end();

    listenFd_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listenFd_ < 0) return false;

    int yes = 1;
    if (::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) {
        end();
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        end();
        return false;
    }

    if (::listen(listenFd_, backlog) != 0) {
        end();
        return false;
    }

    return true;
}

void SocketServer::end() {
    SocketUtils::closeSocket(listenFd_);
}

bool SocketServer::waitUntilReadable(int fd, uint32_t timeoutMs) {
    if (fd < 0) return false;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    timeval tv = makeTimeval(timeoutMs);
    const int rc = ::select(fd + 1, &rfds, nullptr, nullptr, &tv);

    return rc > 0 && FD_ISSET(fd, &rfds);
}

SocketServer::Connection SocketServer::accept(uint32_t timeoutMs) {
    if (listenFd_ < 0) return Connection{};
    if (!waitUntilReadable(listenFd_, timeoutMs)) return Connection{};

    sockaddr_in clientAddr{};
    socklen_t addrLen = sizeof(clientAddr);

    const int fd = ::accept(listenFd_, reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);
    if (fd < 0) return Connection{};

    if (!SocketUtils::setRecvTimeout(fd, timeoutMs) ||
        !SocketUtils::setSendTimeout(fd, timeoutMs)) {
        int tmp = fd;
        SocketUtils::closeSocket(tmp);
        return Connection{};
    }
    const IPAddress peerIp(clientAddr.sin_addr.s_addr);
    const uint16_t peerPort = ntohs(clientAddr.sin_port);
    return Connection(fd, peerIp, peerPort);
}

} // namespace tcpmsg