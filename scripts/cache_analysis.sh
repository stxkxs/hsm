#!/usr/bin/env bash
#
# Cache-Grind Analysis for Timing Side-Channel Detection
#
# This script runs Valgrind's cache-grind tool on cryptographic operations
# to detect cache-timing side channels. It analyzes cache miss patterns to
# identify secret-dependent memory access.
#
# Usage:
#   ./scripts/cache_analysis.sh [test_name]
#
# Requirements:
#   - Valgrind installed (brew install valgrind on macOS, apt install valgrind on Linux)
#   - Cargo test binaries compiled in release mode
#
# Security Goals:
#   - Detect secret-dependent cache misses
#   - Identify data-dependent memory access patterns
#   - Verify cache-oblivious algorithms
#
# References:
#   - "Cache-Timing Attacks on AES" (Bernstein, 2005)
#   - "Spectre Attacks" (Kocher et al., 2018)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_OUTPUT_DIR="$PROJECT_ROOT/target/cache-analysis"

# Create output directory
mkdir -p "$CACHE_OUTPUT_DIR"

echo "=================================================="
echo "HSM Cache-Grind Timing Side-Channel Analysis"
echo "=================================================="
echo ""

# Check if Valgrind is installed
if ! command -v valgrind &> /dev/null; then
    echo -e "${RED}ERROR: Valgrind is not installed${NC}"
    echo ""
    echo "Install Valgrind:"
    echo "  macOS:  brew install valgrind"
    echo "  Ubuntu: sudo apt install valgrind"
    echo ""
    exit 1
fi

echo "Valgrind version:"
valgrind --version
echo ""

# Build tests in release mode for accurate analysis
echo "Building crypto-engine tests in release mode..."
cd "$PROJECT_ROOT/crates/crypto-engine"
cargo test --release --no-run
echo ""

# Find the test binary
TEST_BINARY=$(find "$PROJECT_ROOT/target/release/deps" -name 'crypto_engine-*' -type f -executable | grep -v '\.d$' | head -1)

if [ -z "$TEST_BINARY" ]; then
    echo -e "${RED}ERROR: Could not find test binary${NC}"
    echo "Run 'cargo test --release --no-run' first"
    exit 1
fi

echo "Test binary: $TEST_BINARY"
echo ""

# Run cache-grind on constant-time operations tests
echo "Running cache-grind analysis on constant-time operations..."
echo ""

CACHEGRIND_OUT="$CACHE_OUTPUT_DIR/cachegrind.out"

# Run valgrind with cache-grind
# --cache-sim=yes enables cache simulation
# --branch-sim=yes enables branch prediction simulation
# --cachegrind-out-file specifies output file
valgrind \
    --tool=cachegrind \
    --cache-sim=yes \
    --branch-sim=yes \
    --cachegrind-out-file="$CACHEGRIND_OUT" \
    "$TEST_BINARY" constant_time 2>&1 | tee "$CACHE_OUTPUT_DIR/valgrind.log"

echo ""
echo "=================================================="
echo "Cache-Grind Analysis Results"
echo "=================================================="
echo ""

# Parse cache-grind output
if [ -f "$CACHEGRIND_OUT" ]; then
    echo "Cache statistics:"
    echo ""

    # Extract summary statistics
    grep -E "^(I |D |LL)" "$CACHEGRIND_OUT" || true

    echo ""
    echo "Detailed analysis saved to:"
    echo "  $CACHEGRIND_OUT"
    echo ""

    # Use cg_annotate if available for detailed analysis
    if command -v cg_annotate &> /dev/null; then
        echo "Generating annotated source..."
        CG_ANNOTATE_OUT="$CACHE_OUTPUT_DIR/cache_annotate.txt"
        cg_annotate "$CACHEGRIND_OUT" > "$CG_ANNOTATE_OUT"
        echo "  $CG_ANNOTATE_OUT"
        echo ""

        # Show top cache-intensive functions
        echo "Top cache-intensive functions:"
        head -50 "$CG_ANNOTATE_OUT" | tail -20
        echo ""
    fi

    echo -e "${GREEN}✓ Cache-grind analysis complete${NC}"
else
    echo -e "${RED}✗ Cache-grind output file not found${NC}"
    exit 1
fi

echo ""
echo "=================================================="
echo "Secret-Dependent Access Analysis"
echo "=================================================="
echo ""

# Look for potential timing leaks in the log
echo "Checking for potential timing leaks..."
echo ""

# Check for high variance in cache misses
# (This is a simplified heuristic - manual review is still needed)
if grep -q "mispredicts" "$CACHE_OUTPUT_DIR/valgrind.log"; then
    echo -e "${YELLOW}⚠  Branch mispredictions detected - review for secret-dependent branches${NC}"
else
    echo -e "${GREEN}✓ No obvious branch prediction issues${NC}"
fi

echo ""
echo "=================================================="
echo "Manual Review Required"
echo "=================================================="
echo ""
echo "To verify constant-time properties, manually review:"
echo "  1. Cache miss patterns should be independent of secret data"
echo "  2. Branch prediction should not depend on secret values"
echo "  3. Memory access patterns should be data-oblivious"
echo ""
echo "Compare cache-grind results for different input classes:"
echo "  - Valid vs invalid signatures"
echo "  - Matching vs non-matching tags"
echo "  - Different positions of mismatches"
echo ""
echo "If cache misses correlate with secret data, investigate:"
echo "  - Table lookups with secret-dependent indices"
echo "  - Conditional branches on secret values"
echo "  - Variable-time instructions (division, modulo)"
echo ""

exit 0
