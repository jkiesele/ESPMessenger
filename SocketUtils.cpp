#include "SocketUtils.h"

namespace tcpmsg {

namespace {
    timeval makeTimeval(uint32_t timeoutMs) {
        timeval tv{};
        tv.tv_sec  = static_cast<long>(timeoutMs / 1000UL);
        tv.tv_usec = static_cast<long>((timeoutMs % 1000UL) * 1000UL);
        return tv;
    }
}

bool SocketUtils::setRecvTimeout(int fd, uint32_t timeoutMs) {
    if (fd < 0) return false;
    const timeval tv = makeTimeval(timeoutMs);
    return ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

bool SocketUtils::setSendTimeout(int fd, uint32_t timeoutMs) {
    if (fd < 0) return false;
    const timeval tv = makeTimeval(timeoutMs);
    return ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
}

bool SocketUtils::waitUntilWritable(int fd, uint32_t timeoutMs) {
    if (fd < 0) return false;

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    const timeval tv = makeTimeval(timeoutMs);

    const int rc = ::select(fd + 1, nullptr, &wfds, nullptr, const_cast<timeval*>(&tv));
    if (rc <= 0) return false;

    int soError = 0;
    socklen_t len = sizeof(soError);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) != 0) return false;

    return soError == 0;
}

int SocketUtils::connectTo(const IPAddress& ip, uint16_t port, uint32_t timeoutMs) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (fd < 0) return kInvalidFd;

    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        int tmp = fd;
        closeSocket(tmp);
        return kInvalidFd;
    }

    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        int tmp = fd;
        closeSocket(tmp);
        return kInvalidFd;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = static_cast<uint32_t>(ip);

    const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc != 0) {
        if (errno != EINPROGRESS) {
            int tmp = fd;
            closeSocket(tmp);
            return kInvalidFd;
        }

        if (!waitUntilWritable(fd, timeoutMs)) {
            int tmp = fd;
            closeSocket(tmp);
            return kInvalidFd;
        }
    }

    if (::fcntl(fd, F_SETFL, flags) != 0) {
        int tmp = fd;
        closeSocket(tmp);
        return kInvalidFd;
    }

    if (!setRecvTimeout(fd, timeoutMs) || !setSendTimeout(fd, timeoutMs)) {
        int tmp = fd;
        closeSocket(tmp);
        return kInvalidFd;
    }

    return fd;
}

bool SocketUtils::readExact(int fd, uint8_t* dst, size_t len, uint32_t timeoutMs) {
    if (fd < 0 || (!dst && len > 0)) return false;
    if (!setRecvTimeout(fd, timeoutMs)) return false;

    size_t done = 0;
    while (done < len) {
        const int rc = ::recv(fd, dst + done, len - done, 0);
        if (rc > 0) {
            done += static_cast<size_t>(rc);
            continue;
        }
        if (rc == 0) return false;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
        return false;
    }
    return true;
}

bool SocketUtils::writeExact(int fd, const uint8_t* src, size_t len, uint32_t timeoutMs) {
    if (fd < 0 || (!src && len > 0)) return false;
    if (!setSendTimeout(fd, timeoutMs)) return false;

    size_t done = 0;
    while (done < len) {
        const int rc = ::send(fd, src + done, len - done, 0);
        if (rc > 0) {
            done += static_cast<size_t>(rc);
            continue;
        }
        if (rc == 0) return false;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
        return false;
    }
    return true;
}

void SocketUtils::closeSocket(int& fd) {
    if (fd >= 0) {
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
        fd = kInvalidFd;
    }
}

} // namespace tcpmsg