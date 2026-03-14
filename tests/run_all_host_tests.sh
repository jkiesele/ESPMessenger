#!/usr/bin/env bash
set -euo pipefail

CXX="${CXX:-c++}"
CXXFLAGS=(-std=c++17 -Wall -Wextra -pedantic)
PTHREAD=(-pthread)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$ROOT_DIR/tests"
BUILD_DIR="$TEST_DIR/build"
INCLUDES=(-I"$ROOT_DIR")

mkdir -p "$BUILD_DIR"
    
build() {
  local out="$1"
  shift
  echo "[BUILD] $out"
  "$CXX" "${CXXFLAGS[@]}" "${INCLUDES[@]}" "$@" -o "$BUILD_DIR/$out"
}

build_pthread() {
  local out="$1"
  shift
  echo "[BUILD] $out"
  "$CXX" "${CXXFLAGS[@]}" "${PTHREAD[@]}" "${INCLUDES[@]}" "$@" -o "$BUILD_DIR/$out"
}

run() {
  local exe="$1"
  shift || true
  echo
  echo "[RUN ] $exe $*"
  "$BUILD_DIR/$exe" "$@"
}

cd "$ROOT_DIR"

# Build all host tests
build test_client \
  SocketUtils.cpp SocketServer.cpp \
  tests/test_client.cpp

build test_frame_accumulator \
  FrameAccumulator.cpp \
  tests/test_frame_accumulator.cpp

build_pthread test_inbound_connection \
  SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp InboundConnection.cpp \
  tests/test_inbound_connection.cpp

build test_messenger_codec \
  MessengerCodec.cpp \
  tests/test_messenger_codec.cpp

build_pthread test_outbound_transaction \
  SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp OutboundTransaction.cpp \
  tests/test_outbound_transaction.cpp

build_pthread test_platform_mutex \
  PlatformMutex.cpp \
  tests/test_platform_mutex.cpp

build_pthread test_platform_threads \
  PlatformThreads.cpp \
  tests/test_platform_threads.cpp

build test_server \
  SocketUtils.cpp SocketServer.cpp \
  tests/test_server.cpp

build_pthread test_tcp_messenger_failures_0 \
  SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp InboundConnection.cpp \
  OutboundTransaction.cpp PlatformThreads.cpp PlatformMutex.cpp TCPTransport.cpp \
  MessengerCodec.cpp TCPMessenger.cpp EncryptionHandler.cpp \
  tests/test_tcp_messenger_failures_0.cpp

build_pthread test_tcp_messenger \
  SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp InboundConnection.cpp \
  OutboundTransaction.cpp PlatformThreads.cpp PlatformMutex.cpp TCPTransport.cpp \
  MessengerCodec.cpp TCPMessenger.cpp EncryptionHandler.cpp \
  tests/test_tcp_messenger.cpp

build_pthread test_tcp_transport \
  SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp InboundConnection.cpp \
  OutboundTransaction.cpp PlatformThreads.cpp PlatformMutex.cpp TCPTransport.cpp \
  tests/test_tcp_transport.cpp

build test_transport_codec \
  FrameAccumulator.cpp TransportCodec.cpp \
  tests/test_transport_codec.cpp

# Run the simple self-contained tests
run test_frame_accumulator
run test_messenger_codec
run test_transport_codec
run test_platform_mutex
run test_platform_threads
run test_outbound_transaction
run test_inbound_connection
run test_tcp_transport
run test_tcp_messenger
run test_tcp_messenger_failures_0

# Run the socket smoke/integration script if present
if [[ -x "$TEST_DIR/run_socket_tests.sh" ]]; then
  echo
  echo "[RUN ] run_socket_tests.sh"
  (
    cd "$TEST_DIR"
    ./run_socket_tests.sh
  )
elif [[ -f "$TEST_DIR/run_socket_tests.sh" ]]; then
  echo
  echo "[RUN ] run_socket_tests.sh"
  (
    cd "$TEST_DIR"
    bash ./run_socket_tests.sh
  )
else
  echo
  echo "[WARN] tests/run_socket_tests.sh not found, skipping"
fi

echo
echo "All host tests completed successfully."