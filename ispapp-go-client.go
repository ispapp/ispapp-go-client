package main

import (
	"flag"
	"log"
	"fmt"
	"net"
	"strings"
	"bytes"
	"os/exec"
	"runtime"
	"net/url"
	"os"
	"os/signal"
	"time"
	"strconv"
	"github.com/gorilla/websocket"
	"crypto/x509"
	"crypto/tls"
	"io/ioutil"
	"encoding/json"
	"github.com/go-ping/ping"
)

var addr string = ""
var loginInterface string = ""
var pemFile string = ""
var hostKey string = ""
var clientInfo string = "ispapp-go-client-0.1"
var pingHosts [][]byte

type Client struct {
	Authed			bool	`json:"authed"`
	Host			Host	`json:"host"`
}

type WsResponse struct {
	Type			string	`json:"type"`
	Client			Client	`json:"client"`
	LastColUpdateOffsetSec	int64	`json:"lastColUpdateOffsetSec"`
	LastUpdateOffsetSec	int64	`json:"lastUpdateOffsetSec"`
	UpdateFast		bool	`json:"updateFast"`
	Error			string	`json:"error"`
}

type Host struct {
	Login			string
	Make			string
	Model			string
	ModelNumber		string
	SerialNumber		string
	CPUInfo			string
	OS			string
	OSVersion		string
	Firmware		string
	FirmwareVersion		string
	OSBuildDate		uint64
	UpdateIntervalSeconds	int64		`json:"updateIntervalSeconds"`
	OutageIntervalSeconds	int64		`json:"outageIntervalSeconds"`
}

type Interface struct {
	If			string	`json:"if,omitempty"`
	RecBytes		uint64	`json:"recBytes"`
	RecPackets		uint64	`json:"recPackets"`
	RecErrors		uint64	`json:"recErrors"`
	RecDrops		uint64	`json:"recDrops"`
	SentBytes		uint64	`json:"sentBytes"`
	SentPackets		uint64	`json:"sentPackets"`
	SentErrors		uint64	`json:"sentErrors"`
	SentDrops		uint64	`json:"sentDrops"`
}

type Ping struct {
	Host		string	`json:"host,omitempty"`
	AvgRtt		float64	`json:"avgRtt"`
	MinRtt		float64	`json:"minRtt"`
	MaxRtt		float64	`json:"maxRtt"`
	Loss		int64	`json:"loss"`
}

type Load struct {
	One			int64	`json:"one"`
	Five			int64	`json:"five"`
	Fifteen			int64	`json:"fifteen"`
	ProcessCount		int64	`json:"processCount"`
}

type Memory struct {
	Total			int64	`json:"total"`
	Free			int64	`json:"free"`
	Buffers			int64	`json:"buffers"`
	Cache			int64	`json:"cache"`
}

type Disk struct {
	Mount			string	`json:"mount,omitempty"`
	Used			int64	`json:"used"`
	Avail			int64	`json:"avail"`
}

type System struct {
	Load		Load	`json:"load"`
	Memory		Memory	`json:"memory"`
	Disks		[]Disk	`json:"disks"`
}

type Station struct {
	Mac			string	`json:"mac,omitempty"`
	Info			string	`json:"info"`
	Rssi			int64	`json:"rssi"`
	RecBytes		int64	`json:"recBytes"`
	SentBytes		int64	`json:"sentBytes"`
}

type Wap struct {
	Interface		string		`json:"interface,omitempty"`
	Stations		[]Station	`json:"stations"`
	Signal0			int64		`json:"signal0"`
	Signal1			int64		`json:"signal1"`
	Signal2			int64		`json:"signal2"`
	Signal3			int64		`json:"signal3"`
	Noise			int64		`json:"noise"`
}

type Mac string

type Arp struct {
	Interface		string	`json:"interface,omitempty"`
	Macs			[]Mac	`json:"macs"`
}

type Collector struct {
	Interface	[]Interface	`json:"interface"`
	Ping		[]Ping		`json:"ping"`
	System		System		`json:"system"`
	Wap		[]Wap		`json:"wap"`
	Arp		[]Arp		`json:"arp"`
}

func new_websocket(host Host) {

	u := url.URL{Scheme: "wss", Host: addr, Path: "/ws"}
	fmt.Printf("connecting to %s\n", u.String())

	roots := x509.NewCertPool()

	rootPEM, rperr := ioutil.ReadFile(pemFile)
	if rperr != nil {
		fmt.Println(rperr)
	} else {

		ok := roots.AppendCertsFromPEM(rootPEM)
		if !ok {
			log.Fatal("failed to parse root certificate")
		}
	}
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots}}

	c, _, err := d.Dial(u.String(), nil)
	if err != nil {
		fmt.Println("dial:", err)
		fmt.Println("reconnecting")
		time.Sleep(5 * time.Second)
		new_websocket(host)
	}
	defer c.Close()

	var authed bool = false
	var sendAt = time.Now().Unix()

	go func() {
		for {

			if (c == nil) {
				return
			}

			_, message, err := c.ReadMessage()
			if err != nil {
				fmt.Println("error reading wss server response for " + host.Login + ":", err)
				return
			}
			//fmt.Printf("\nrecv: %s", message)

			var hr WsResponse

			err = json.Unmarshal(message, &hr)
			if (err != nil) {
				fmt.Printf("error decoding json: %s\n", err.Error())
			}

			//fmt.Printf("hr: %+v\n\n", hr)

			if (hr.UpdateFast) {
				// update every second
				sendAt = time.Now().Unix() + 1
			} else if (hr.Type == "error") {
				fmt.Printf("ERROR Received from Server: %s\n", hr.Error)
			} else {
				// send with the outage interval normally
				var sendOffset = host.OutageIntervalSeconds - hr.LastUpdateOffsetSec

				if (sendOffset > host.UpdateIntervalSeconds - hr.LastColUpdateOffsetSec) {
					// use the required time for a collector update
					// if it is less than the outage interval
					sendOffset = host.UpdateIntervalSeconds - hr.LastColUpdateOffsetSec
				}

				fmt.Printf("%s sending update in %d seconds.\n", host.Login, sendOffset)

				sendAt = time.Now().Unix() + sendOffset
			}

			if (hr.Client.Authed) {
				authed = true
				// make an update request immediately following the config request
				sendAt = time.Now().Unix() + 1

				// set the config response intervals
				host.OutageIntervalSeconds = hr.Client.Host.OutageIntervalSeconds
				host.UpdateIntervalSeconds = hr.Client.Host.UpdateIntervalSeconds

				fmt.Println(host.Login + " authed via config request")
			}

		}
	}()

	s := fmt.Sprintf("{\"type\": \"%s\", \"login\": \"%s\", \"key\": \"%s\", \"clientInfo\": \"%s\", \"hardwareMake\": \"%s\", \"hardwareModel\": \"%s\", \"hardwareModelNumber\": \"%s\", \"hardwareSerialNumber\": \"%s\", \"hardwareCpuInfo\": \"%s\", \"os\": \"%s\", \"osVersion\": \"%s\", \"fw\": \"%s\", \"fwVersion\": \"%s\", \"osBuildDate\": %d}", "config", host.Login, hostKey, clientInfo, host.Make, host.Model, host.ModelNumber, host.SerialNumber, host.CPUInfo, host.OS, host.OSVersion, host.Firmware, host.FirmwareVersion, host.OSBuildDate)

	if (c != nil) {

		//fmt.Printf("sending: %s\n", s)

		err = c.WriteMessage(websocket.TextMessage, []byte(s))
		if err != nil {
			fmt.Println("error sending config request for " + host.Login + ":", err)
		} else {
			fmt.Println("sent config request for " + host.Login)
		}
	} else {
		fmt.Println("did not send config request because websocket was nil for " + host.Login)
	}

	for {

		//fmt.Printf("attempt for %s\t\t\tauthed=%t\tsendAt=%d\tsendAtDiff=%d\n", host.Login, authed, sendAt, time.Now().Unix()-sendAt)

		if (time.Now().Unix() > sendAt) {

			if (authed) {

				var u_json string = ""
				var cols Collector

				cols.Ping = make([]Ping, len(pingHosts))

				for pingIndex := range pingHosts {

					fmt.Printf("pinging %s\n", pingHosts[pingIndex])

					// ping the ping servers
					pingError := false
					pinger, perr := ping.NewPinger(string(pingHosts[pingIndex]))
					if perr != nil {
						fmt.Println("ping error: ", perr)
						pingError = true
					}

					pinger.Count = 5
					pinger.Timeout = time.Second * 1
					pinger.Interval = time.Millisecond * 20
					pinger.SetPrivileged(true)
					perr = pinger.Run() // Blocks until finished.
					if perr != nil {
						fmt.Println("ping error: ", perr)
						pingError = true
					}
					stats := pinger.Statistics()

					cols.Ping[pingIndex].Host = string(pingHosts[pingIndex])
					if (!pingError) {
						cols.Ping[pingIndex].AvgRtt = float64(stats.AvgRtt) / float64(time.Millisecond)
						cols.Ping[pingIndex].MinRtt = float64(stats.MinRtt) / float64(time.Millisecond)
						cols.Ping[pingIndex].MaxRtt = float64(stats.MaxRtt) / float64(time.Millisecond)
						cols.Ping[pingIndex].Loss = int64(stats.PacketLoss)
					}
					//fmt.Printf("ping stats: %+v\n", stats)

				}

				cols_json, jerr := json.Marshal(cols)
				if jerr != nil {
					fmt.Println("error with json.Marshal for update", jerr)
				}

				// get wan ip
				var ipaddrstr, port, iperr = net.SplitHostPort(c.LocalAddr().String())
				_ = port
				_ = iperr

				now := time.Now()

				// get uptime
				var uptime_sec uint64 = 0

				if (runtime.GOOS == "darwin") {

					cmd := exec.Command("sysctl", "-n", "kern.boottime")
					cmd.Stdin = strings.NewReader(" ")
					var out bytes.Buffer
					var stderr bytes.Buffer
					cmd.Stdout = &out
					cmd.Stderr = &stderr
					_ = cmd.Run()
					// split output
					// expects
					// { sec = 1641489984, usec = 872066 } Thu Jan  6 20:26:24 2022
					oo := strings.Split(out.String(), " ")
					oo[3] = strings.TrimRight(oo[3], ",")
					//fmt.Printf("oo: %q\n", oo[3])
					uptime_sec, _ = strconv.ParseUint(oo[3], 10, 64)
					uptime_sec = uint64(now.Unix()) - uptime_sec

				} else if (runtime.GOOS == "linux") {

					cmd := exec.Command("awk", "'{print $1}'", "/proc/uptime")
					cmd.Stdin = strings.NewReader(" ")
					var out bytes.Buffer
					var stderr bytes.Buffer
					cmd.Stdout = &out
					cmd.Stderr = &stderr
					_ = cmd.Run()
					uptime_sec, _ = strconv.ParseUint(strings.Replace(out.String(), "\n", "", -1), 10, 64)

				} else if (runtime.GOOS == "windows") {
				}

				// make the update json string
				s := fmt.Sprintf("{\"type\": \"%s\", \"wanIp\": \"%s\"%s, \"collectors\": %s, \"uptime\": %d}", "update", ipaddrstr, u_json, string(cols_json), uptime_sec)

				fmt.Printf("sending update to ISPApp: %s\n", s)

				err = c.WriteMessage(websocket.TextMessage, []byte(s))
				if err != nil {
					fmt.Println("write:", err)
					break
				}

				// give the recv loop time to update sendAt
				time.Sleep(1 * time.Second)

			}

		} else {
			//fmt.Printf("%s sleeping for %d seconds\n", host.Login, sendAt-time.Now().Unix())
			time.Sleep(400 * time.Millisecond)
			continue
		}

	}

	// force a reconnect after 5 seconds
	fmt.Println("reconnecting")
	time.Sleep(5 * time.Second)
	new_websocket(host)

}

func main() {

	fmt.Println("USAGE:")
	fmt.Println("\t./ispapp-go-client -addr=\"dev.ispapp.co:8550\" -certPath=\"/home/ec2-user/ispapp-keys/__ispapp_co.ca-bundle\" -hostKey=\"asdfasdfasdf -if=\"en0\"\"\n\n")

	flag.StringVar(&addr, "addr", "unknown", "ISPApp address:port")
	flag.StringVar(&loginInterface, "if", "", "Name of Interface for Login MAC Address")
	flag.StringVar(&pemFile, "certPath", "/home/ec2-user/ispapp-keys/__ispapp_co.ca-bundle", "TLS certificate file path")
	flag.StringVar(&hostKey, "hostKey", "", "ISPApp Host Key")

	flag.Parse()

	if (addr == "unknown") {
		os.Exit(1)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	// add ping hosts
	pingHosts = make([][]byte, 0)
	pingHosts = append(pingHosts, []byte("aws-eu-west-2-ping.ispapp.co"))
	pingHosts = append(pingHosts, []byte("aws-us-east-1-ping.ispapp.co"))
	pingHosts = append(pingHosts, []byte("aws-us-west-1-ping.ispapp.co"))
	pingHosts = append(pingHosts, []byte("aws-sa-east-1-ping.ispapp.co"))

	// connect this host's mac address as a websocket client
	var h1 Host

	// get mac address
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {

		if (loginInterface == "") {
			if (interf.Name == "en0" || interf.Name == "en1" || interf.Name == "eth0") {
				// the first wifi or wired interface on a MacOS, Linux
				h1.Login = interf.HardwareAddr.String()
				break
			}
		} else {
			if (interf.Name == loginInterface) {
				h1.Login = interf.HardwareAddr.String()
				break
			}
		}

	}

	if (h1.Login == "") {
		fmt.Printf("Specify the network interface to use the MAC Address of for the login with -if\n")
		os.Exit(1)
	}

	// set the computer information
	h1.OS = runtime.GOOS

	fmt.Printf("GOOS: %s\n", runtime.GOOS)
	fmt.Printf("Getting system information...\n")

	if (runtime.GOOS == "darwin") {

		h1.Make = "Apple"

		// run system_profiler and get json output
		cmd := exec.Command("system_profiler", "-json")
		cmd.Stdin = strings.NewReader(" ")
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		_ = cmd.Run()
		//fmt.Printf("%s\n", out.String())

		var omap map[string]interface{}
		if jerr := json.Unmarshal(out.Bytes(), &omap); jerr != nil {
			log.Fatal(jerr)
		}
		//fmt.Printf("%+v\n", omap)

		// print all root keys from system_profiler
		/*
		for n := range omap {
			fmt.Printf("%s\n", n)
		}
		*/

		//fmt.Printf("%+v\n", omap["SPHardwareDataType"])
		//fmt.Printf("%+v\n", omap["SPSoftwareDataType"])
		// the data is unmarshaled to an interface{} after the root level
		// so use a type assertion `.()` of []interface{} to access the array, in order to access the [0] element
		// then use a type assertion of map[string]interface{} to access level root+1 fields
		// or make a struct
		//fmt.Printf("%+v\n", omap["SPSoftwareDataType"].([]interface{})[0].(map[string]interface{})["os_version"])

		// what you would expect to be able to do and what you need to do because of it being compiled code
		//h1.CPUInfo = omap["SPHardwareDataType"]["cpu_type"] + " " + omap["SPHardwareDataType"]["current_processor_speed"]
		h1.CPUInfo = omap["SPHardwareDataType"].([]interface{})[0].(map[string]interface{})["cpu_type"].(string) + " " + omap["SPHardwareDataType"].([]interface{})[0].(map[string]interface{})["current_processor_speed"].(string)
		//h1.Model = omap["SPHardwareDataType"]["machine_name"]
		h1.Model = omap["SPHardwareDataType"].([]interface{})[0].(map[string]interface{})["machine_name"].(string)
		//h1.ModelNumber = omap["SPHardwareDataType"]["machine_model"]
		h1.ModelNumber = omap["SPHardwareDataType"].([]interface{})[0].(map[string]interface{})["machine_model"].(string)
		//h1.SerialNumber = omap["SPHardwareDataType"]["serial_number"]
		h1.SerialNumber = omap["SPHardwareDataType"].([]interface{})[0].(map[string]interface{})["serial_number"].(string)
		//h1.OSVersion = omap["SPSoftwareDataType"]["os_version"]
		h1.OSVersion = omap["SPSoftwareDataType"].([]interface{})[0].(map[string]interface{})["os_version"].(string)

		// get os from uname
		cmd = exec.Command("uname", "-srm")
		cmd.Stdin = strings.NewReader(" ")
		out.Reset()
		stderr.Reset()
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		_ = cmd.Run()
		h1.OS = strings.Replace(out.String(), "\n", "", -1)

	} else if (runtime.GOOS == "linux") {

		// get os from uname
		cmd := exec.Command("uname", "-srm")
		cmd.Stdin = strings.NewReader(" ")
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		_ = cmd.Run()
		h1.OS = strings.Replace(out.String(), "\n", "", -1)

	} else if (runtime.GOOS == "windows") {

		h1.OS = "Windows"

	}

	// create a socket to the listener
	go new_websocket(h1)

	for {

		select {
			// wait for interrupt
		case <-interrupt:
			fmt.Println("close")
			os.Exit(0)
		}

	}

}
