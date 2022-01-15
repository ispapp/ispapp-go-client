# Installing

Get the file and run it!

## MacOS

Replace `##DOMAIN##` and `##HOSTKEY##` then run this command in Terminal.app.

```
curl -o ~/ispapp-go-client-mac https://raw.githubusercontent.com/ispapp/ispapp-go-client/master/ispapp-go-client-mac && sudo ~/ispapp-go-client-mac -addr "##DOMAIN##" -hostKey "##HOSTKEY##"
```

# Building and Running Locally

Set `GO111MODULE=off` so the module src is installed.

```
export GO111MODULE=off
go get github.com/go-ping/ping
go get github.com/gorilla/websocket
go get github.com/google/gopacket
```

Run as root for ping privileges.

```
sudo GO111MODULE=off go run ispapp-go-client.go -domain "dev.ispapp.co" -hostKey "yourhostkey"
```

# Packaging

Storing a ca-bundle file in ispapp-go-client.go for ease of distribution.

```
cd tools
go ca-bundle-to-hex-string.go -in /path/to/domain.ca-bundle
```

Then copy the text output with no newlines as the `ca_bundle_hex` variable data in /ispapp-go-client.go.

# Building with Static Linking

To build binaries that work without installation or library requirements on the target OS and Architecture.

###MacOS/darwin on amd64 (intel macs)

```
GO111MODULE=off CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -o ispapp-go-client-darwin-amd64 ispapp-go-client.go
```

###MacOS/darwin on arm (m1 macs)

```
GO111MODULE=off CGO_ENABLED=0 GOOS=darwin GOARCH=arm go build -a -o ispapp-go-client-darwin-amd64 ispapp-go-client.go
```

###Linux on amd64

```
GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o ispapp-go-client-darwin-amd64 ispapp-go-client.go
```

###Windows on amd64

```
GO111MODULE=off CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -o ispapp-go-client-darwin-amd64 ispapp-go-client.go
```

Here's a list of os/arch that are supported (there may be more now, `go tool dist list`).

```
android/386
android/amd64
android/arm
android/arm64
darwin/386
darwin/amd64
darwin/arm
darwin/arm64
dragonfly/amd64
freebsd/386
freebsd/amd64
freebsd/arm
linux/386
linux/amd64
linux/arm
linux/arm64
linux/mips
linux/mips64
linux/mips64le
linux/mipsle
linux/ppc64
linux/ppc64le
linux/s390x
nacl/386
nacl/amd64p32
nacl/arm
netbsd/386
netbsd/amd64
netbsd/arm
openbsd/386
openbsd/amd64
openbsd/arm
plan9/386
plan9/amd64
plan9/arm
solaris/amd64
windows/386
windows/amd64
```
