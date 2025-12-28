#!/bin/bash
set -e

DOCKER_USERNAME="ashfn0"
IMAGE_NAME="islechat"
TAG="latest"
FULL_IMAGE="$DOCKER_USERNAME/$IMAGE_NAME:$TAG"
PLATFORM="linux/amd64"

echo "=== Creating/reusing buildx builder for better emulation ==="
docker buildx create --use --name cross-builder --driver docker-container --bootstrap || true

echo "=== Building and pushing with buildx (better amd64 emulation) ==="
docker buildx build --platform "$PLATFORM" \
  -t "$FULL_IMAGE" \
  --push .   # --push sends directly to Hub (no local image needed)

echo "=== Done! Image pushed: $FULL_IMAGE ==="