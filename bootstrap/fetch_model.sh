#!/usr/bin/env bash
#
# Fetch the local LLM weights for the optional in-project llama.cpp service.
#
# The model file is ~4.7 GB and is deliberately NOT committed to git (see
# .gitignore). This script downloads it once into ./models/, where the
# docker-compose "llama" service (profile: localllm) mounts it read-only.
#
# Usage (from the repository root):
#     ./bootstrap/fetch_model.sh
#
# Idempotent: if the file already exists and is the expected size it does
# nothing; a partial download is resumed rather than restarted.
#
set -euo pipefail

# Repo root = parent of this script's directory, so it works from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL_DIR="${ROOT}/models"

MODEL_FILE="Qwen3-8B-Q4_K_M.gguf"
MODEL_URL="https://huggingface.co/Qwen/Qwen3-8B-GGUF/resolve/main/${MODEL_FILE}"
# Minimum plausible size for the complete file (~4.7 GB). A real download is a
# hair over 5.0e9 bytes; anything well under this is a truncated/error download.
# A threshold rather than an exact byte count on purpose: different Q4_K_M builds
# of the same model differ by a few KB, and an exact match would keep re-fetching
# a perfectly good file.
MIN_BYTES=4800000000

DEST="${MODEL_DIR}/${MODEL_FILE}"

mkdir -p "${MODEL_DIR}"

filesize() { stat -c%s "$1" 2>/dev/null || stat -f%z "$1"; }

if [[ -f "${DEST}" ]]; then
    actual="$(filesize "${DEST}")"
    if (( actual >= MIN_BYTES )); then
        echo "==> ${MODEL_FILE} already present (${actual} bytes). Nothing to do."
        exit 0
    fi
    echo "==> ${MODEL_FILE} exists but is only ${actual} bytes; resuming download."
fi

echo "==> Downloading ${MODEL_FILE} (~4.7 GB) into ${MODEL_DIR}/"
echo "    Source: ${MODEL_URL}"

# -L follow redirects (HF -> CDN), -C - resume a partial file, --fail on HTTP error.
if command -v curl >/dev/null 2>&1; then
    curl -L --fail -C - -o "${DEST}" "${MODEL_URL}"
elif command -v wget >/dev/null 2>&1; then
    wget -c -O "${DEST}" "${MODEL_URL}"
else
    echo "ERROR: neither curl nor wget is installed." >&2
    exit 1
fi

actual="$(filesize "${DEST}")"
if (( actual < MIN_BYTES )); then
    echo "ERROR: download finished at ${actual} bytes (< ${MIN_BYTES})." >&2
    echo "       The file is likely truncated. Re-run this script to resume." >&2
    exit 1
fi

echo "==> Done. ${DEST} (${actual} bytes)"
echo "    Start the local model server with:"
echo "        docker compose --profile localllm up -d llama"
