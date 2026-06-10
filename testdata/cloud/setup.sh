#!/usr/bin/env bash
# Bring up a local S3-compatible object store for the cloud integration tests
# and create the `test-pcaps` bucket. The tests upload their own fixtures.
#
# Two backends are supported:
#
#   MinIO via Docker (preferred, matches CI):
#       docker compose -f testdata/cloud/docker-compose.yml up -d
#       export PCAPSQL_S3_TEST_ENDPOINT=http://127.0.0.1:9000
#
#   SeaweedFS native binary (Docker-free fallback; used when image registries
#   are unreachable). This script implements that fallback:
#       ./testdata/cloud/setup.sh seaweedfs
#       export PCAPSQL_S3_TEST_ENDPOINT=http://127.0.0.1:8333
#
# Then run:
#   AWS_ACCESS_KEY_ID=pcapsqlkey AWS_SECRET_ACCESS_KEY=pcapsqlsecret \
#   AWS_REGION=us-east-1 \
#     cargo test -p pcapsql-datafusion --features s3 --test cloud_integration
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUCKET="${PCAPSQL_S3_TEST_BUCKET:-test-pcaps}"
MODE="${1:-docker}"

case "$MODE" in
  docker|minio)
    echo "Starting MinIO via docker compose..."
    docker compose -f "$HERE/docker-compose.yml" up -d
    echo "MinIO up on http://127.0.0.1:9000 (bucket: $BUCKET)"
    echo "export PCAPSQL_S3_TEST_ENDPOINT=http://127.0.0.1:9000"
    ;;

  seaweedfs|weed)
    # Docker-free fallback using the SeaweedFS binary on PATH (or ./weed).
    WEED="${WEED_BIN:-weed}"
    if ! command -v "$WEED" >/dev/null 2>&1 && [ -x "$HERE/weed" ]; then
      WEED="$HERE/weed"
    fi
    DATA="$(mktemp -d)"
    echo "Starting SeaweedFS S3 (data dir: $DATA)..."
    "$WEED" server -dir="$DATA" -ip=127.0.0.1 -s3 \
      -s3.config="$HERE/s3.json" -s3.port=8333 >"$DATA/weed.log" 2>&1 &
    echo $! > "$DATA/weed.pid"
    # Wait for the S3 endpoint to come up.
    for _ in $(seq 1 30); do
      code="$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8333 || true)"
      [ -n "$code" ] && [ "$code" != "000" ] && break
      sleep 1
    done
    echo "s3.bucket.create -name $BUCKET" | "$WEED" shell >/dev/null 2>&1 || true
    echo "SeaweedFS up on http://127.0.0.1:8333 (bucket: $BUCKET, pid $(cat "$DATA/weed.pid"))"
    echo "export PCAPSQL_S3_TEST_ENDPOINT=http://127.0.0.1:8333"
    ;;

  *)
    echo "usage: $0 [docker|seaweedfs]" >&2
    exit 2
    ;;
esac
