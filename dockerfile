FROM golang:1.25.5-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN apk add --no-cache gcc musl-dev
RUN CGO_ENABLED=1 go build -o isle-chat .
FROM alpine:3.19
RUN addgroup -g 1000 islechat && \
    adduser -D -u 1000 -G islechat -h /home/islechat islechat
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    ncurses-terminfo \
    ncurses-terminfo-base
RUN mkdir -p /home/islechat/.ssh && \
    chown -R islechat:islechat /home/islechat
COPY --from=builder /app/isle-chat /usr/local/bin/isle-chat
RUN chown islechat:islechat /usr/local/bin/isle-chat
USER islechat
WORKDIR /home/islechat
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/isle-chat"]