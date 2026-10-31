#!/usr/bin/env bash
# AEGIS-X — Mac/Linux convenience wrapper for the test runner.
# Just forwards to the real (cross-platform) Python script.
#
# Usage:
#   ./tests/run_all_tests.sh
#   ./tests/run_all_tests.sh --fast
#   ./tests/run_all_tests.sh --module backend

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/run_all_tests.py" "$@"
exit $?
