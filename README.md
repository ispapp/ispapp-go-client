# Installing

Here are the instructions for each different Operating System.

First you need to <a href="https://go.dev" target="_new">install Go</a> on your Operating System.

## MacOS

Paste this into the Terminal.

```
export GO111MODULE=off
go get github.com/go-ping/ping
go get github.com/gorilla/websocket
go get github.com/google/gopacket

git clone https://github.com/ispapp/ispapp-go-client
cd ispapp-go-client
```

Then modify the -hostKey and -domain arguments and run this command.

```
sudo GO111MODULE=off go run ispapp-go-client.go -domain "dev.ispapp.co" -hostKey "yourhostkey"
```

## Windows

Paste this into the Command Prompt. (Start->Run->cmd)

```
export GO111MODULE=off
go get github.com/go-ping/ping
go get github.com/gorilla/websocket
go get github.com/google/gopacket

git clone https://github.com/ispapp/ispapp-go-client
cd ispapp-go-client
```

Then modify the -hostKey and -domain arguments and run this command.

You need to run this command as Administrator, press Windows+R to open the Run box.  Type "cmd" into the box and then press Ctrl+Shift+Enter to run the command as administrator.

```
GO111MODULE=off go run ispapp-go-client.go -domain "dev.ispapp.co" -hostKey "yourhostkey"
```

## Linux

Paste this into a shell.

```
export GO111MODULE=off
go get github.com/go-ping/ping
go get github.com/gorilla/websocket
go get github.com/google/gopacket

git clone https://github.com/ispapp/ispapp-go-client
cd ispapp-go-client
```

Then modify the -hostKey and -domain arguments and run this command.

```
sudo GO111MODULE=off go run ispapp-go-client.go -domain "dev.ispapp.co" -hostKey "yourhostkey"
```

# Building with Static Linking

To build binaries that work without installation or library requirements on the target OS and Architecture.

### MacOS/darwin on amd64 (intel macs)

```
GO111MODULE=off CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -o ispapp-go-client-darwin-amd64 ispapp-go-client.go
```

### MacOS/darwin on arm (m1 macs)

```
GO111MODULE=off CGO_ENABLED=0 GOOS=darwin GOARCH=arm go build -a -o ispapp-go-client-darwin-arm ispapp-go-client.go
```

### Linux on amd64

```
GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o ispapp-go-client-linux-amd64 ispapp-go-client.go
```

### Windows on amd64

```
GO111MODULE=off CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -o ispapp-go-client-windows-amd64 ispapp-go-client.go
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

# Packaging a non-os bundled ca certificate in the program

Storing a ca-bundle file in ispapp-go-client.go for ease of distribution.

```
cd tools
go ca-bundle-to-hex-string.go -in /path/to/domain.ca-bundle
```

Then copy the text output with no newlines as the `ca_bundle_hex` variable data in /ispapp-go-client.go.

# license

The project ispapp-linux-client is licensed per the GNU General Public License, version 2

A copy is in the project directory, as a file named LICENSE
