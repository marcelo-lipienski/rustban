#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${RUSTBAN_IMAGE:-rustban:latest}"
CROSS_IMAGE_TAG="rustban-cross:build"
ALL_TARGETS="x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl"

EXTRACT=0
CROSS_TARGETS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --extract)
      EXTRACT=1
      shift
      ;;
    --target)
      if [[ $# -lt 2 ]]; then
        echo "Missing argument for --target" >&2
        exit 1
      fi
      CROSS_TARGETS="${CROSS_TARGETS:+${CROSS_TARGETS} }$2"
      shift 2
      ;;
    --all-targets)
      CROSS_TARGETS="${ALL_TARGETS}"
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--extract] [--target <triple>] [--all-targets]"
      echo "  Builds rustban in --release mode exclusively inside Docker."
      echo "  --extract          Copy the compiled native release binary from the runtime image to ./dist/rustban"
      echo "  --target <triple>  Cross-compile a specific target into ./dist/<triple>/rustban"
      echo "                     Supported: ${ALL_TARGETS}"
      echo "  --all-targets      Cross-compile all 4 release targets (x86_64/aarch64 x gnu/musl) into ./dist/<triple>/rustban"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -n "${CROSS_TARGETS}" ]]; then
  echo "==> Cross-compiling release targets inside Docker: ${CROSS_TARGETS}"
  docker build \
    --target cross-builder \
    --build-arg "RUSTBAN_VERSION=${RUSTBAN_VERSION:-}" \
    --build-arg "TARGETS=${CROSS_TARGETS}" \
    -t "${CROSS_IMAGE_TAG}" \
    "${ROOT_DIR}"

  mkdir -p "${ROOT_DIR}/dist"
  cid="$(docker create "${CROSS_IMAGE_TAG}")"
  trap 'docker rm -f "${cid}" >/dev/null 2>&1 || true' EXIT

  for target in ${CROSS_TARGETS}; do
    mkdir -p "${ROOT_DIR}/dist/${target}"
    docker cp "${cid}:/out/${target}/rustban" "${ROOT_DIR}/dist/${target}/rustban"
    chmod 0755 "${ROOT_DIR}/dist/${target}/rustban"
    echo "==> Extracted ${target} binary to ${ROOT_DIR}/dist/${target}/rustban"
  done
  exit 0
fi

echo "==> Building release image '${IMAGE_TAG}' inside Docker..."
docker build --target runtime --build-arg "RUSTBAN_VERSION=${RUSTBAN_VERSION:-}" -t "${IMAGE_TAG}" "${ROOT_DIR}"

if [[ "${EXTRACT}" -eq 1 ]]; then
  mkdir -p "${ROOT_DIR}/dist"
  cid="$(docker create "${IMAGE_TAG}")"
  trap 'docker rm -f "${cid}" >/dev/null 2>&1 || true' EXIT
  docker cp "${cid}:/usr/local/bin/rustban" "${ROOT_DIR}/dist/rustban"
  chmod +x "${ROOT_DIR}/dist/rustban"
  echo "==> Extracted release binary to ${ROOT_DIR}/dist/rustban"
fi
