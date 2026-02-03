#!/bin/bash
set -euo pipefail

# Script to run tests and update VS Code test interface

# Get the project root directory (where the script is located)
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
FRONTEND_DIR="$SCRIPT_DIR/apps/desktop"

# Source common utilities
source "$SCRIPT_DIR/scripts/common.sh"

echo -e "${C_YELLOW}Running tests and updating test interface...${C_NC}"

# Run Rust tests
echo -e "${C_BLUE}Running Rust tests...${C_NC}"
rust_test_result=0
cargo test --workspace --manifest-path "$SCRIPT_DIR/Cargo.toml" || rust_test_result=$?

# Run frontend tests if present
echo -e "${C_BLUE}Running frontend tests (if present)...${C_NC}"
frontend_test_result=0
npm --prefix "$FRONTEND_DIR" run test --if-present || frontend_test_result=$?

echo -e "${C_YELLOW}Tests completed. Refresh the test interface in VS Code (Ctrl+Shift+P -> 'Test: Refresh Tests').${C_NC}"

if [ $rust_test_result -ne 0 ] || [ $frontend_test_result -ne 0 ]; then
    echo -e "${C_RED}Some tests failed!${C_NC}"
    exit 1
else
    echo -e "${C_GREEN}All tests passed!${C_NC}"
    exit 0
fi
