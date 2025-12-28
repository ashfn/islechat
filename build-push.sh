#!/bin/bash
set -e

DOCKER_USERNAME="ashfn0"
IMAGE_NAME="islechat"
TAG="latest"
FULL_IMAGE="$DOCKER_USERNAME/$IMAGE_NAME:$TAG"
PLATFORM="linux/amd64"

echo "=== Setting up buildx builder (reusing if exists) ==="

# Remove old builder if it exists, then recreate fresh (simplest & most reliable)
docker buildx rm fast-builder || true
docker buildx create --use --name fast-builder \
  --driver docker-container \
  --bootstrap \
  --config /dev/stdin <<EOF
[worker.docker-container]
  cpus = $(sysctl -n hw.logicalcpu)
  memory = 8589934592  # 8GB
  [[features]]
    binfmt = true
EOF

echo "Builder ready: using $(sysctl -n hw.logicalcpu) cores + 8GB RAM"

echo "=== Building and pushing $FULL_IMAGE ($PLATFORM) ==="

docker buildx build \
  --platform "$PLATFORM" \
  --push \
  --pull \
  --progress=plain \
  -t "$FULL_IMAGE" \
  .

echo ""
echo "=== SUCCESS! ==="
echo "Image pushed: $FULL_IMAGE"
echo "Check it here: https://hub.docker.com/r/$DOCKER_USERNAME/$IMAGE_NAME/tags"