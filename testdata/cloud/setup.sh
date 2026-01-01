#!/bin/bash
# Generate and upload test PCAP files to LocalStack S3 for integration testing.
#
# This script generates ALL test files dynamically - no binary files in git.
#
# Prerequisites:
#   - LocalStack running (docker compose up -d)
#   - AWS CLI installed (or awslocal)
#   - uvx (for Python dependency management)
#   - compression tools: gzip, zstd, lz4
#
# Usage:
#   ./setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENDPOINT="http://localhost:4566"
BUCKET="test-pcaps"
REGION="us-east-1"
OUTPUT_DIR="/tmp/generated"

# Use awslocal if available, otherwise aws with endpoint override
if command -v awslocal &> /dev/null; then
    AWS="awslocal"
else
    AWS="aws --endpoint-url=$ENDPOINT --region=$REGION"
fi

echo "=== Step 1: Generate test PCAP files ==="
echo "Using uvx to run generator with scapy..."

# Generate all test files
uvx --with scapy python "$SCRIPT_DIR/../scripts/gen_format_tests.py" --output-dir "$OUTPUT_DIR"

echo ""
echo "=== Step 2: Wait for LocalStack ==="
echo "Waiting for LocalStack to be ready..."
until curl -s "$ENDPOINT/_localstack/health" | grep -q '"s3": *"available"'; do
    sleep 1
done
echo "LocalStack is ready!"

echo ""
echo "=== Step 3: Create S3 bucket ==="
$AWS s3 mb "s3://$BUCKET" 2>/dev/null || echo "Bucket already exists"

echo ""
echo "=== Step 4: Upload generated PCAP files ==="
for f in "$OUTPUT_DIR"/*.pcap "$OUTPUT_DIR"/*.pcapng; do
    if [ -f "$f" ]; then
        echo "Uploading $(basename "$f")..."
        $AWS s3 cp "$f" "s3://$BUCKET/$(basename "$f")"
    fi
done

echo ""
echo "=== Step 5: Create and upload compressed versions ==="
# Use small_dns.pcap as the base for compression tests
if [ -f "$OUTPUT_DIR/small_dns.pcap" ]; then
    echo "Creating gzip compressed version..."
    gzip -c "$OUTPUT_DIR/small_dns.pcap" > "$OUTPUT_DIR/small_dns.pcap.gz"
    $AWS s3 cp "$OUTPUT_DIR/small_dns.pcap.gz" "s3://$BUCKET/"

    if command -v zstd &> /dev/null; then
        echo "Creating zstd compressed version..."
        zstd -q -c "$OUTPUT_DIR/small_dns.pcap" > "$OUTPUT_DIR/small_dns.pcap.zst"
        $AWS s3 cp "$OUTPUT_DIR/small_dns.pcap.zst" "s3://$BUCKET/"
    else
        echo "Warning: zstd not installed, skipping zstd compression test"
    fi

    if command -v lz4 &> /dev/null; then
        echo "Creating lz4 compressed version..."
        lz4 -q -c "$OUTPUT_DIR/small_dns.pcap" > "$OUTPUT_DIR/small_dns.pcap.lz4"
        $AWS s3 cp "$OUTPUT_DIR/small_dns.pcap.lz4" "s3://$BUCKET/"
    else
        echo "Warning: lz4 not installed, skipping lz4 compression test"
    fi
fi

echo ""
echo "=== Uploaded files ==="
$AWS s3 ls "s3://$BUCKET/"

echo ""
echo "=== Setup complete! ==="
echo "Run integration tests with:"
echo "  cargo test -p pcapsql-datafusion --features s3 --test cloud_integration -- --ignored"
