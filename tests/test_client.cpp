
// c++ -std=c++17 -Wall -Wextra -pedantic SocketUtils.cpp SocketServer.cpp test_client.cpp -o test_client

#include <cstdint>
#include <iostream>
#include <string>

#include "SocketUtils.h"

namespace {

constexpr uint16_t kPort = 12345;
constexpr uint32_t kTimeoutMs = 2000;
const IPAddress kIp(127, 0, 0, 1);

using TestFn = bool(*)();

bool connectSocket(int& fd) {
    fd = tcpmsg::SocketUtils::connectTo(kIp, kPort, kTimeoutMs);
    return fd >= 0;
}

bool testNormalRoundtrip() {
    int fd = tcpmsg::SocketUtils::kInvalidFd;
    if (!connectSocket(fd)) return false;

    const uint8_t msg[] = {'H', 'E', 'L', 'L', 'O', '\n'};
    uint8_t reply[6] = {};

    const bool ok =
        tcpmsg::SocketUtils::writeExact(fd, msg, sizeof(msg), kTimeoutMs) &&
        tcpmsg::SocketUtils::readExact(fd, reply, sizeof(reply), kTimeoutMs);

    tcpmsg::SocketUtils::closeSocket(fd);

    if (!ok) return false;

    const uint8_t expected[] = {'W', 'O', 'R', 'L', 'D', '\n'};
    for (size_t i = 0; i < sizeof(expected); ++i) {
        if (reply[i] != expected[i]) return false;
    }
    return true;
}

bool testReadTimeout() {
    int fd = tcpmsg::SocketUtils::kInvalidFd;
    if (!connectSocket(fd)) return false;

    const uint8_t msg[] = {'H', 'E', 'L', 'L', 'O', '\n'};
    const bool writeOk = tcpmsg::SocketUtils::writeExact(fd, msg, sizeof(msg), kTimeoutMs);

    uint8_t reply[6] = {};
    const bool readOk = tcpmsg::SocketUtils::readExact(fd, reply, sizeof(reply), 1000);

    tcpmsg::SocketUtils::closeSocket(fd);

    return writeOk && !readOk;
}

bool testPeerClosesEarly() {
    int fd = tcpmsg::SocketUtils::kInvalidFd;
    if (!connectSocket(fd)) return false;

    uint8_t reply[6] = {};
    const bool readOk = tcpmsg::SocketUtils::readExact(fd, reply, sizeof(reply), kTimeoutMs);

    tcpmsg::SocketUtils::closeSocket(fd);

    return !readOk;
}

bool testConnectToClosedPort() {
    const uint16_t closedPort = 54321;
    int fd = tcpmsg::SocketUtils::connectTo(kIp, closedPort, 1000);
    if (fd >= 0) {
        tcpmsg::SocketUtils::closeSocket(fd);
        return false;
    }
    return true;
}

bool runTest(const char* name, TestFn fn) {
    std::cout << "[RUN ] " << name << "\n";
    const bool ok = fn();
    std::cout << (ok ? "[ OK ] " : "[FAIL] ") << name << "\n";
    return ok;
}

void printUsage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " <case>\n";
    std::cerr << "Cases: normal | read_timeout | close_early | closed_port\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        printUsage(argv[0]);
        return 10;
    }

    const std::string which = argv[1];
    bool ok = false;

    if (which == "normal")        ok = runTest("normal", testNormalRoundtrip);
    else if (which == "read_timeout") ok = runTest("read_timeout", testReadTimeout);
    else if (which == "close_early")  ok = runTest("close_early", testPeerClosesEarly);
    else if (which == "closed_port")  ok = runTest("closed_port", testConnectToClosedPort);
    else {
        printUsage(argv[0]);
        return 11;
    }

    return ok ? 0 : 1;
}