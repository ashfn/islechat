# syntax=docker/dockerfile:1

# ============ Builder Stage ============
FROM golang:1.25.5-alpine AS builder

# Install dependencies needed for go build
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy only go.mod and go.sum first — this enables Docker layer caching
COPY go.mod go.sum ./

# Download dependencies NATIVELY (fast on your Mac, no emulation)
RUN go mod download && go mod verify

# Now copy the full source code
COPY . .

# Build the binary for linux/amd64 (explicit for consistency)
# Remove -ldflags if you want debug info; add them later for smaller binary if needed
RUN GOOS=linux GOARCH=amd64 go build -o isle-chat .

# ============ Runtime Stage ============
FROM alpine:3.19

# Create non-root user
RUN addgroup -g 1000 islechat && \
    adduser -D -u 1000 -G islechat -h /home/islechat islechat

# Install runtime deps
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    ncurses-terminfo \
    ncurses-terminfo-base

# Create .ssh directory with correct ownership
RUN mkdir -p /home/islechat/.ssh && \
    chown -R islechat:islechat /home/islechat

# Copy the binary from builder
COPY --from=builder /app/isle-chat /usr/local/bin/isle-chat

# Ensure correct ownership and permissions
RUN chown islechat:islechat /usr/local/bin/isle-chat

# Switch to non-root user
USER islechat

# Set working directory
WORKDIR /home/islechat

# Expose SSH port
EXPOSE 2222

# Run the app
ENTRYPOINT ["/usr/local/bin/isle-chat"]