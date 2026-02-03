#!/bin/bash
set -euo pipefail

# Script to run all checks that would be performed in GitHub Actions

# Get the project root directory (where the script is located)
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
FRONTEND_DIR="$SCRIPT_DIR/apps/desktop"

# Source common utilities
source "$SCRIPT_DIR/scripts/common.sh"

echo -e "${C_YELLOW}Running all project checks...${C_NC}"

echo -e "${C_BLUE}Checking Rust code...${C_NC}"
cargo check --workspace --manifest-path "$SCRIPT_DIR/Cargo.toml"

cargo clippy --workspace --manifest-path "$SCRIPT_DIR/Cargo.toml" --all-targets -- -W clippy::pedantic -D warnings

echo -e "${C_BLUE}Running Rust tests...${C_NC}"
cargo test --workspace --manifest-path "$SCRIPT_DIR/Cargo.toml"

echo -e "${C_BLUE}Checking frontend code...${C_NC}"
npm --prefix "$FRONTEND_DIR" run check

echo -e "${C_BLUE}Linting frontend code...${C_NC}"
npm --prefix "$FRONTEND_DIR" run lint -- --config "$SCRIPT_DIR/eslint.config.js"

# Run frontend tests if present
echo -e "${C_BLUE}Running frontend tests (if present)...${C_NC}"
npm --prefix "$FRONTEND_DIR" run test --if-present

echo -e "${C_GREEN}All checks and tests passed!${C_NC}"
