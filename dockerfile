# Build stage
FROM golang:1.25.5-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY . .

RUN go build -o isle-chat .

# Runtime stage
FROM alpine:3.19

# Create non-root user with home directory
RUN addgroup -g 1000 islechat && \
    adduser -D -u 1000 -G islechat -h /home/islechat islechat

RUN apk add --no-cache ca-certificates tzdata
RUN apk add --no-cache ncurses-terminfo ncurses-terminfo-base

# Create .ssh directory for the user
RUN mkdir -p /home/islechat/.ssh && \
    chown -R islechat:islechat /home/islechat

COPY --from=builder /build/isle-chat /usr/local/bin/isle-chat

RUN chown islechat:islechat /usr/local/bin/isle-chat

USER islechat

WORKDIR /home/islechat

EXPOSE 2222

ENTRYPOINT ["/usr/local/bin/isle-chat"]