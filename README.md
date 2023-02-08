# Installing

Install a pcap library and run the executable for your OS.

The compiled binaries are in the root directory.

`./ispapp-go-client-*`

# Windows

Install `npcap` or another pcap library.

Download the .exe file and copy it to your Users directory.

Run the program by clicking Start->Run and entering `cmd`

```
ispapp-go-client-windows-amd64.exe -domain "subdomain.ispapp.co" -hostKey "yourhostkey" -if "Wi-Fi"
```

**Run on Startup with Task Scheduler in Windows 11**

The Task Scheduler won't work without a local account.

1. Go to Windows Settings.
2. Go to Accounts.
3. Click "Your Info".
4. Under Account settings, click "Sign in with a local account instead".

Signout and Sign back in to your computer, you can also remove the Windows Hello PIN only sign in now.

1. Open **Task Scheduler**.
2. Click Create Task (**not** Create Basic Task).
3. Select "Run whether user is logged on or not".
4. Select the "Hidden" checkbox.
5. Name the Task "ispapp-go-client".
6. Click the "Conditions" Tab.
7. Deselect "Start the task only if the computer is on AC power" option.
8. Click the "Settings" Tab.
9. Deselect the "Stop the task if it runs longer than" option.
10. Click the "Triggers" Tab.
11. Click "New".
12. Select "At startup" from "Begin the task" at the top of the window then click OK.
13. Click the "Actions" Tab.
14. Click "New".
15. Click "Browse" for Program/script and select the "ispapp-go-client-windows-amd64.exe" file in your Users directory.
16. Add this string to the "Add arguments" field **without the outer double quotes**: "-domain "subdomain.ispapp.co" -hostKey "yourhostkey" -if "Wi-Fi"".
17. Click OK.
18. Click OK.

# Building

```
export GO111MODULE=off
go get github.com/andrewhodel/ping
go get github.com/gorilla/websocket
go get github.com/andrewhodel/gopacket

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
GO111MODULE=off CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -a -o ispapp-go-client-darwin-amd64 ispapp-go-client.go
```

### MacOS/darwin on arm64 (m1 macs)

```
GO111MODULE=off CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -a -o ispapp-go-client-darwin-arm64 ispapp-go-client.go
```

### Linux on amd64

```
GO111MODULE=off CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -a -o ispapp-go-client-linux-amd64 ispapp-go-client.go
```

### Windows on amd64

```
GO111MODULE=off CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -a -o ispapp-go-client-windows-amd64.exe ispapp-go-client.go
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

The project ispapp-linux-client is licensed per the MIT License
