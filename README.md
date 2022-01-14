Set `GO111MODULE=off` so the module src is installed.

```
export GO111MODULE=off
go get github.com/go-ping/ping
go get github.com/gorilla/websocket
go get github.com/google/gopacket
```

run as root for ping privileges

```
sudo GO111MODULE=off go run ispapp-go-client.go
```
