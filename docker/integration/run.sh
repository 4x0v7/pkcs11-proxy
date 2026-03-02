#!/bin/bash

# Run Docker Compose integration tests (detached mode).
# Works around Docker Compose attach-mode hang on Windows/Docker Desktop
# by starting detached, tailing client logs, then checking output for PASS/FAIL.

COMPOSE_FILE="docker/docker-compose.test.yml"

# Clean slate
docker compose -f "${COMPOSE_FILE}" down -v 2>/dev/null || true

# Start all services detached
docker compose -f "${COMPOSE_FILE}" up -d --force-recreate

# Follow client logs until it exits, capture output
LOGFILE=$(mktemp)
docker compose -f "${COMPOSE_FILE}" logs -f client 2>/dev/null | tee "${LOGFILE}"

# Show server logs
echo ""
echo "=== Server logs ==="
docker compose -f "${COMPOSE_FILE}" logs server 2>/dev/null || true

# Show sslscan output
echo ""
echo "=== sslscan output ==="
docker compose -f "${COMPOSE_FILE}" logs sslscan 2>/dev/null || true

# Clean up
echo ""
docker compose -f "${COMPOSE_FILE}" down -v 2>/dev/null || true

# Determine pass/fail from the client output
if grep -q "ALL INTEGRATION TESTS PASSED" "${LOGFILE}"; then
    echo "=== Integration tests PASSED ==="
    rm -f "${LOGFILE}"
    exit 0
else
    echo "=== Integration tests FAILED ==="
    rm -f "${LOGFILE}"
    exit 1
fi
