# Installing

Get the file and run it!

## MacOS

Replace `##DOMAIN##` and `##HOSTKEY##` then run this command in Terminal.app

```
curl -o ~/ispapp-go-client-mac https://raw.githubusercontent.com/ispapp/ispapp-go-client/master/ispapp-go-client-mac && sudo ~/ispapp-go-client-mac -addr "##DOMAIN##" -hostKey "##HOSTKEY##"
```

# Building

Set `GO111MODULE=off` so the module src is installed.

```
export GO111MODULE=off
go get github.com/go-ping/ping
go get github.com/gorilla/websocket
go get github.com/google/gopacket
```

run as root for ping privileges

```
sudo GO111MODULE=off go run ispapp-go-client.go -domain "dev.ispapp.co" -hostKey "yourhostkey"
```

# Packaging

Storing a ca-bundle file in ispapp-go-client.go for ease of distribution:

```
cd tools
go ca-bundle-to-hex-string.go -in /path/to/domain.ca-bundle
```

Then copy the text output with no newlines as the `ca_bundle_hex` variable data in /ispapp-go-client.go
