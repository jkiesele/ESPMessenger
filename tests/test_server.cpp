//c++ -std=c++17 -Wall -Wextra -pedantic SocketUtils.cpp SocketServer.cpp test_server.cpp -o test_server
#include <cstdint>
#include <iostream>
#include <string>

#include "SocketServer.h"

namespace {

constexpr uint16_t kPort = 12345;
constexpr uint32_t kTimeoutMs = 5000;

void printUsage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " <mode>\n";
    std::cerr << "Modes: normal | no_reply | close_early | accept_timeout\n";
}

int runNormal() {
    tcpmsg::SocketServer server;
    if (!server.begin(kPort)) {
        std::cerr << "server begin failed\n";
        return 1;
    }

    std::cout << "[server] normal: listening on port " << kPort << "\n";

    auto conn = server.accept(kTimeoutMs);
    if (!conn.isValid()) {
        std::cerr << "[server] accept failed\n";
        return 2;
    }

    uint8_t buf[6] = {};
    if (!conn.readExact(buf, sizeof(buf), kTimeoutMs)) {
        std::cerr << "[server] readExact failed\n";
        return 3;
    }

    std::cout << "[server] received: ";
    std::cout.write(reinterpret_cast<const char*>(buf), sizeof(buf));
    std::cout << "\n";

    const uint8_t reply[] = {'W', 'O', 'R', 'L', 'D', '\n'};
    if (!conn.writeExact(reply, sizeof(reply), kTimeoutMs)) {
        std::cerr << "[server] writeExact failed\n";
        return 4;
    }

    std::cout << "[server] reply sent\n";
    return 0;
}

int runNoReply() {
    tcpmsg::SocketServer server;
    if (!server.begin(kPort)) {
        std::cerr << "server begin failed\n";
        return 1;
    }

    std::cout << "[server] no_reply: listening on port " << kPort << "\n";

    auto conn = server.accept(kTimeoutMs);
    if (!conn.isValid()) {
        std::cerr << "[server] accept failed\n";
        return 2;
    }

    uint8_t buf[6] = {};
    if (!conn.readExact(buf, sizeof(buf), kTimeoutMs)) {
        std::cerr << "[server] readExact failed\n";
        return 3;
    }

    std::cout << "[server] received request, intentionally not replying\n";
    return 0;
}

int runCloseEarly() {
    tcpmsg::SocketServer server;
    if (!server.begin(kPort)) {
        std::cerr << "server begin failed\n";
        return 1;
    }

    std::cout << "[server] close_early: listening on port " << kPort << "\n";

    auto conn = server.accept(kTimeoutMs);
    if (!conn.isValid()) {
        std::cerr << "[server] accept failed\n";
        return 2;
    }

    const uint8_t partial[] = {'B', 'Y', 'E'};
    if (!conn.writeExact(partial, sizeof(partial), kTimeoutMs)) {
        std::cerr << "[server] partial write failed\n";
        return 3;
    }

    std::cout << "[server] wrote partial reply and will close now\n";
    conn.close();
    return 0;
}

int runAcceptTimeout() {
    tcpmsg::SocketServer server;
    if (!server.begin(kPort)) {
        std::cerr << "server begin failed\n";
        return 1;
    }

    std::cout << "[server] accept_timeout: waiting for client\n";

    auto conn = server.accept(2000);
    if (conn.isValid()) {
        std::cerr << "[server] unexpected client accepted\n";
        return 2;
    }

    std::cout << "[server] accept timeout behaved as expected\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        printUsage(argv[0]);
        return 10;
    }

    const std::string mode = argv[1];

    if (mode == "normal")        return runNormal();
    if (mode == "no_reply")      return runNoReply();
    if (mode == "close_early")   return runCloseEarly();
    if (mode == "accept_timeout") return runAcceptTimeout();

    printUsage(argv[0]);
    return 11;
}