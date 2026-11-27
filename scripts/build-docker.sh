#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${RUSTBAN_IMAGE:-rustban:latest}"
EXTRACT=0

for arg in "$@"; do
  case "$arg" in
    --extract) EXTRACT=1 ;;
    -h|--help)
      echo "Usage: $0 [--extract]"
      echo "  Builds rustban in --release mode exclusively inside Docker."
      echo "  --extract   Copy the compiled release binary from the image to ./dist/rustban"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

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
