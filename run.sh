go build -o islechat

cleanup() {
    kill 0 2>/dev/null
}
trap cleanup EXIT

./islechat 2>/dev/null &

sleep 1

# ssh user@localhost -p 22223 --

sshpass -p user ssh user@localhost -p 22223