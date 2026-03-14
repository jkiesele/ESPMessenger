#!/usr/bin/env bash
set -euo pipefail

CXX="${CXX:-c++}"
CXXFLAGS="-std=c++17 -Wall -Wextra -pedantic"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

mkdir -p "$BUILD_DIR"

SERVER_BIN="$BUILD_DIR/test_server"
CLIENT_BIN="$BUILD_DIR/test_client"
INCLUDES=(-I"$ROOT_DIR")

build() {
  echo "[BUILD] test_server"
  "$CXX" $CXXFLAGS "${INCLUDES[@]}" \
    "$ROOT_DIR/SocketUtils.cpp" \
    "$ROOT_DIR/SocketServer.cpp" \
    "$SCRIPT_DIR/test_server.cpp" \
    -o "$SERVER_BIN"

  echo "[BUILD] test_client"
  "$CXX" $CXXFLAGS "${INCLUDES[@]}" \
    "$ROOT_DIR/SocketUtils.cpp" \
    "$ROOT_DIR/SocketServer.cpp" \
    "$SCRIPT_DIR/test_client.cpp" \
    -o "$CLIENT_BIN"
}

run_case() {
  local server_mode="$1"
  local client_case="${2:-}"
  local expect_server_rc="${3:-0}"
  local expect_client_rc="${4:-0}"

  echo
  echo "=================================================="
  echo "[CASE] server=${server_mode} client=${client_case:-<none>}"
  echo "=================================================="

  "$SERVER_BIN" "$server_mode" &
  local server_pid=$!

  sleep 0.3

  local client_rc=0
  if [[ -n "$client_case" ]]; then
    set +e
    "$CLIENT_BIN" "$client_case"
    client_rc=$?
    set -e
  fi

  local server_rc=0
  set +e
  wait "$server_pid"
  server_rc=$?
  set -e

  echo "[INFO] server rc=$server_rc, expected=$expect_server_rc"
  echo "[INFO] client rc=$client_rc, expected=$expect_client_rc"

  if [[ "$server_rc" -ne "$expect_server_rc" ]]; then
    echo "[FAIL] server return code mismatch"
    exit 1
  fi

  if [[ "$client_rc" -ne "$expect_client_rc" ]]; then
    echo "[FAIL] client return code mismatch"
    exit 1
  fi

  echo "[ OK ] case passed"
}

main() {
  build

  run_case normal         normal        0 0
  run_case no_reply       read_timeout  0 0
  run_case close_early    close_early   0 0
  run_case accept_timeout ""            0 0

  echo
  echo "=================================================="
  echo "[CASE] client=closed_port"
  echo "=================================================="
  "$CLIENT_BIN" closed_port

  echo
  echo "All socket tests passed."
}

main "$@"