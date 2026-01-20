#!/bin/bash
# Nuclei scanner wrapper for DAST-MVP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES_DIR="$SCRIPT_DIR/nuclei-templates"
TARGET_URL="${TARGET_URL:-http://localhost:3000}"
BEARER_TOKEN="${BEARER_TOKEN:-}"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           Nuclei Scanner - DAST-MVP                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Target: $TARGET_URL"
echo "Templates: $TEMPLATES_DIR"
echo ""

# Check if Nuclei is installed
if ! command -v nuclei &> /dev/null; then
    echo "Error: nuclei not found. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

# Check if target is reachable
if ! curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL" | grep -q "200\|302\|400\|401\|403\|404\|500"; then
    echo "Error: Target $TARGET_URL is not reachable"
    exit 1
fi

# Build arguments
ARGS="-u $TARGET_URL -t $TEMPLATES_DIR"

# Add severity filter if specified
if [ -n "$SEVERITY" ]; then
    ARGS="$ARGS -severity $SEVERITY"
fi

# Add Bearer token for templates that need authentication
if [ -n "$BEARER_TOKEN" ]; then
    ARGS="$ARGS -var bearer_token=$BEARER_TOKEN"
    echo "Using Bearer token for authenticated endpoints"
fi

# Add optional output formats
if [ -n "$OUTPUT_FILE" ]; then
    ARGS="$ARGS -o $OUTPUT_FILE"
fi

if [ -n "$JSON_OUTPUT" ]; then
    ARGS="$ARGS -json | tee $JSON_OUTPUT"
fi

echo "Running: nuclei $ARGS"
echo ""

# Run Nuclei
eval "nuclei $ARGS"

echo ""
echo "✓ Scan complete!"
