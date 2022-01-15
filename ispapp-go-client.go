package main

import (
	"flag"
	"log"
	"fmt"
	"net"
	"context"
	"strings"
	"bytes"
	b64 "encoding/base64"
	"encoding/hex"
	"os/exec"
	"runtime"
	"net/url"
	"os"
	"os/signal"
	"time"
	"strconv"
	"github.com/gorilla/websocket"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"crypto/x509"
	"crypto/tls"
	"io/ioutil"
	"encoding/json"
	"github.com/go-ping/ping"
)

var ca_bundle_hex string = "2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494947457a4343412f75674177494241674951665674524a725232756848626442594c76464d4e707a414e42676b71686b69473977304241517746414443420a6944454c4d416b474131554542684d4356564d78457a415242674e5642416754436b356c6479424b5a584a7a5a586b784644415342674e56424163544330706c0a636e4e6c65534244615852354d523477484159445651514b457856556147556756564e46556c525356564e554945356c64486476636d73784c6a417342674e560a42414d544a56565452564a55636e567a64434253553045675132567964476c6d61574e6864476c76626942426458526f62334a7064486b774868634e4d5467780a4d5441794d4441774d4441775768634e4d7a41784d6a4d784d6a4d314f545535576a43426a7a454c4d416b474131554542684d4352304978477a415a42674e560a42416754456b64795a5746305a584967545746755932686c6333526c636a45514d4134474131554542784d48553246735a6d39795a4445594d425947413155450a43684d505532566a64476c6e6279424d615731706447566b4d5463774e51594456515144457935545a574e306157647649464a545153424562323168615734670a566d46736157526864476c76626942545a574e31636d556755325679646d567949454e424d494942496a414e42676b71686b6947397730424151454641414f430a415138414d49494243674b4341514541316e4d7a31746338494e414130686446754e592b4236492f783048754d6a444a73477a39394a2f4c457067504c542b4e0a5451454d6767385866324975366268496566735767303674317a496c6b37634876376c5150366c4d7730417136546e2f3259484b48785979516471414a726b6a0a656f63674875502f494a6f386c555276683355476b4543304d704d5743524149497a3753335963506231315246476f4b6163565041584a707a394f54544730450a6f4b4d62676e36786d726e74785a37464e3369666d6767302b315975574d514a44675a6b57377733335047664b47696f567243536f317966753469594342736b0a486173776861367673433665657033427745496334674c773675424b30752b51447254425142627762345643536d5433704443672f7238756f7964616a6f74590a754b334447526545592b317656763244793241307848532b357033623465546c7967786646514944415141426f344942626a434341576f77487759445652306a0a42426777466f415555336d2f57716f7253733955674f48596d384364387249445a737377485159445652304f424259454649324d5873525572597268642b6d620a2b5a7346346267426a5748684d41344741315564447745422f77514541774942686a415342674e5648524d4241663845434441474151482f416745414d4230470a413155644a5151574d425147434373474151554642774d42426767724267454642516344416a416242674e5648534145464441534d41594742465564494141770a434159475a34454d415149424d464147413155644877524a4d456377526142446f45474750326830644841364c79396a636d777564584e6c636e527964584e300a4c6d4e76625339565530565356484a3163335253553046445a584a3061575a7059324630615739755158563061473979615852354c6d4e7962444232426767720a4267454642516342415152714d476777507759494b775942425155484d414b474d326830644841364c79396a636e517564584e6c636e527964584e304c6d4e760a625339565530565356484a3163335253553046425a475255636e567a64454e424c6d4e796444416c4267677242674546425163774159595a6148523063446f760a4c32396a6333417564584e6c636e527964584e304c6d4e766254414e42676b71686b6947397730424151774641414f43416745414d7239687651354977302f480a756b644e2b4a78344751486345783241622f7a44634c52536d6a457a6d6c64532b7a476561365476564b714a6a5541586150675245487a5379724878565962480a37724d326b5962324f56472f527238506f4c71303933354a78436f324635376b61446c367235524f566d2b79657a752f436f61397a63563348414f344f4c47690a4831392b32347263526b69326141725073725730346a546b5a366b345a676c6530726a386e5367364630416e776e4a4f4b66306850487a50452f75574c4d55780a525030543764576271576c6f64337a7534662b6b2b54593443464d356f6f51306e426e7a766736733153513336794f6f654e4454352b2b53523252694f534c760a7876635276694b46786d5a454a43614f45444b4e794a4f754235364450692f5a2b6656476a6d4f2b77656130334b624e496169474370585a4c6f556d477633380a73625a58516d3256305450324f525147676b45343959395933494262704e56396c586a397035762f2f63576f6161736d3536656b42596462716265346f79414c0a6c366c466864327a692b574a4e34347044667747462f593451413543354249472b33767a7868466f59742f6a6d505154324256506937467032524267764751710a366a4733354c576a4f6853624a754d4c652f30436a72615a77546958575462327148536968725a6536385a6b36732b676f2f6c756e726f74456261476d4168590a4c636d734a575479586e57304f4d477566317047672b7052797262786d5245316136567165385941734f6634766d537972636a4338617a6a5565716b6b2b42350a794f4742514d6b4b572b4553504d46674b754f5877496c43797054505270675361627559304d4c5444584a4c5232376c6b3851794b474f48512b53774d6a344b0a3030752f493573554b5545726d6751666b793378787a6c49504b3161456e383d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949466754434342476d6741774942416749514f584a454f766b697431485830327751335445316c54414e42676b71686b69473977304241517746414442370a4d517377435159445651514745774a48516a45624d426b47413155454341775352334a6c5958526c6369424e5957356a6147567a644756794d524177446759440a56515148444164545957786d62334a6b4d526f77474159445651514b44424644623231765a4738675130456754476c746158526c5a4445684d423847413155450a417777595155464249454e6c636e52705a6d6c6a5958526c49464e6c636e5a705932567a4d423458445445354d444d784d6a41774d4441774d466f58445449340a4d54497a4d54497a4e546b314f566f7767596778437a414a42674e5642415954416c56544d524d7745515944565151494577704f5a586367536d5679633256350a4d52517745675944565151484577744b5a584a7a5a586b6751326c30655445654d4277474131554543684d565647686c4946565452564a55556c56545643424f0a5a58523362334a724d5334774c41594456515144457956565530565356484a3163335167556c4e4249454e6c636e52705a6d6c6a5958527062323467515856300a61473979615852354d494943496a414e42676b71686b6947397730424151454641414f43416738414d49494343674b434167454167424a6c467a594f773973490a73394373567731323763306e3030797455494e6834716f6754516b745a416e637a6f6d667a4432703750625077647a7830374857657a636f45537448326a6e470a76446f5a74462b6d765832646f324e43746e6279715473726b666a696239447346694351435437693648544a474c535231474a6b32332b6a42764749474771510a496a79382f68507768785237397551666a74546b556359525a305949556375474646512f7644502b666d79632f786164474c31526a6a576d70326249636d66620a49576178314a7434413842514f756a4d384e79386e6b7a2b727757574e5239585772662f7a766b3974797932396c5464794f63534f6b327554497133584a71300a74794139796e38694e4b352b4f32686d4155546e415535475535737a59506555766c4d336b484e44387a4c44552b2f6271763530546d6e48613478676b3937450a78777a6634544b757a4a4d37555869565a3476755056622b444e4270447873503879556d617a4e74393235482b6e4e443558344f705761784b58777968474e560a6963514e775a4e554d426b54724e4e394e366672585470734e567a625164635332716c4a43392f5967496f4a6b324b4f745762504a596a4e684c6978503651350a44396b436e757353544a56383832734671563457673879345a2b4c6f4535334d57344c54544c5074572f2f6535584f73497a7374414c38315658514a5364684a0a5742702f6b6a626d555a494f38795a3948453058764d6e735179625176304666514b6c455250535a353165486e6c41665631536f5076313059792b785547554a0a356c68434c6b4d61544c54774a55645a2b6751656b39516d526b705167624c65766e69332f47635634636c5868423450593962705972725758315575366c7a470a4b4167454a546d3444697570386b79584841632f44564c3137653876676738434177454141614f42386a4342377a416642674e5648534d4547444157674253670a45516f6a50706278422b7a6972796e766771562f3044436b7444416442674e56485134454667515555336d2f57716f7253733955674f48596d384364387249440a5a73737744675944565230504151482f42415144416747474d41384741315564457745422f7751464d414d4241663877455159445652306742416f77434441470a42675256485341414d454d4741315564487751384d446f774f4b41326f4453474d6d6830644841364c79396a636d7775593239746232527659324575593239740a4c30464251554e6c636e52705a6d6c6a5958526c55325679646d6c6a5a584d7559334a734d445147434373474151554642774542424367774a6a416b426767720a4267454642516377415959596148523063446f764c32396a63334175593239746232527659324575593239744d413047435371475349623344514542444155410a413449424151415968314863644345396e4972674a37637a3043374d3750446d7931345233694a766d33574f6e6e4c2b354e622b71682b636c6933764130702b0a7276534e62334938517a7641502b7534333179717163617538767a5937714e37512f61474e6e7755344d3330397a2f2b33726930697643526c7637395132522b0a2f637a53416146396666675a47636c434b784f2f57497536704b4a6d424861496b55344d6952544f6f6b334a4d724f363642516176484878572f4242433567410a43694944454f554d73666e4e6b6a635a37547678354471322b5555544a6e577675367276503374334f394c45417045394751445446317735327a3937474131460a7a5a4f466c69396433316b57547a39527664564647442f74536f376f426d4630497861314456427a4a305248667842646953707268544555784f6970616b79410a764770347a37682f6a6e5a796d5179642f746552434261686f312b560a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949454d6a43434178716741774942416749424154414e42676b71686b69473977304241515546414442374d517377435159445651514745774a48516a45620a4d426b47413155454341775352334a6c5958526c6369424e5957356a6147567a644756794d5241774467594456515148444164545957786d62334a6b4d526f770a474159445651514b44424644623231765a4738675130456754476c746158526c5a4445684d42384741315545417777595155464249454e6c636e52705a6d6c6a0a5958526c49464e6c636e5a705932567a4d423458445441304d4445774d5441774d4441774d466f58445449344d54497a4d54497a4e546b314f566f77657a454c0a4d416b474131554542684d4352304978477a415a42674e564241674d456b64795a5746305a584967545746755932686c6333526c636a45514d413447413155450a42777748553246735a6d39795a4445614d4267474131554543677752513239746232527649454e424945787062576c305a5751784954416642674e5642414d4d0a47454642515342445a584a3061575a70593246305a5342545a584a3261574e6c637a4343415349774451594a4b6f5a496876634e4151454242514144676745500a4144434341516f4367674542414c35416e665275346570326878784e5255534f766b6249677761647753722b47422b4f35414c363836746455496f574d5175610a4274444663434c4e5353315559387932626d6847433150717930776b774c78795475727846613730564a6f5343734e36736a4e673474714a56664d69575050650a334d2f76673461696a4a52506e326a796d4a42476843664864722f6a7a445573693134485a47574377456977714a4835595a39324946436f6b63646d746574340a59674e5738496f61452b6f786f7836676d6630343976596e4d6c6876422f5672755073554b362b3371737a575931397a6a4e6f466d616734714d735865445a520a724f6d65394867366a63385032554c696d4179724c35384f416437766e356c4a385333667248524e473569315238586c4b6448356b426a485970792b6738636d0a657a364b4a636641335a336d4e576751494a3250324e3753773453634456376f4c386b434177454141614f42774443427654416442674e5648513445466751550a6f42454b497a3657385166733471387037344b6c66394177704c517744675944565230504151482f42415144416745474d41384741315564457745422f7751460a4d414d4241663877657759445652306642485177636a41346f4461674e4959796148523063446f764c324e796243356a623231765a47396a5953356a623230760a515546425132567964476c6d61574e68644756545a584a3261574e6c6379356a636d77774e7141306f444b474d476830644841364c79396a636d7775593239740a623252764c6d356c64433942515546445a584a3061575a70593246305a564e6c636e5a705932567a4c6d4e796244414e42676b71686b694739773042415155460a41414f4341514541434662384176436236502b6b2b745a37786b53417a6b2f4578665941574d796d747277555357674564756a6d376c337341673967316f31510a4745386d5467486a3572436c37722b3864465242762f333845726a485431723069574146663243334255727a3976484376385335644961324c5831727a4e4c7a0a527430767875427177384d30417978396c7431617767366e43706e424259757244432f7a58447250624464564359666555304273574f2f387471746c626754320a4739773834466f567870375a38566c494d43466c41327a733653467a374a73446f6541337261415647492f3675674c4f7079797045424d73314f55494a7173690a6c3244346b463530314b4b615537337971576a676f6d3743313279786f772b65762b746f3531627972764c6a4b7a6736435947316134585876693374507871330a736d506939574973677452714145465138546d446e3558704e70615962673d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0d0a"

var domain string = ""
var port int = 8550
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
	Cmd			string	`json:"cmd"`
	Ws_Id			string	`json:"ws_id"`
	UuidV4			string	`json:"uuidv4"`
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
	WanIfName		string
	UpdateIntervalSeconds	int64		`json:"updateIntervalSeconds"`
	OutageIntervalSeconds	int64		`json:"outageIntervalSeconds"`
	CwrC			uint64		`json:"cwrC"`
	EceC			uint64		`json:"eceC"`
	RstC			uint64		`json:"rstC"`
	SynC			uint64		`json:"synC"`
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

type Counter struct {
	Name			string	`json:"name"`
	Point			uint64	`json:"point"`
}

type Collector struct {
	Interface	[]Interface	`json:"interface"`
	Ping		[]Ping		`json:"ping"`
	System		System		`json:"system"`
	Wap		[]Wap		`json:"wap"`
	Arp		[]Arp		`json:"arp"`
	Counter		[]Counter	`json:"counter"`
}

func new_websocket(host *Host) {

	u := url.URL{Scheme: "wss", Host: domain + ":" + strconv.Itoa(port), Path: "/ws"}
	fmt.Printf("connecting to %s\n", u.String())

	roots := x509.NewCertPool()

	if (ca_bundle_hex != "") {

		// use the hex data in this file
		// convienent for distributing binary files
		// because often operating systems do not include ca files

		ca_s, _ := hex.DecodeString(ca_bundle_hex)
		ok := roots.AppendCertsFromPEM(ca_s)
		if !ok {
			log.Fatal("failed to parse root certificate")
		}

	} else {

		// use the file provided as a command line option

		rootPEM, rperr := ioutil.ReadFile(pemFile)
		if rperr != nil {
			fmt.Println(rperr)
		} else {

			ok := roots.AppendCertsFromPEM(rootPEM)
			if !ok {
				log.Fatal("failed to parse root certificate")
			}

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

	// set host.WanIfName
	var ipaddrstr, port, iperr = net.SplitHostPort(c.LocalAddr().String())
	_ = port
	_ = iperr

	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			var found = false
			for index, addr := range addrs {
				fmt.Println("[", index, "]", interf.Name, ">", addr)
				if (strings.Contains(addr.String(), ipaddrstr)) {
					found = true
					break
				}
			}
			if (found) {
				fmt.Printf("wan interface found: %s\n", interf.Name)
				host.WanIfName = interf.Name
				break
			}
		}
	}

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

			if (hr.Client.Authed && hr.Type == "config") {

				authed = true

				// make an update request immediately following the config request
				sendAt = time.Now().Unix() + 1

				// set the config response intervals
				host.OutageIntervalSeconds = hr.Client.Host.OutageIntervalSeconds
				host.UpdateIntervalSeconds = hr.Client.Host.UpdateIntervalSeconds

				fmt.Println(host.Login + " authed via config request")

			}

			if (hr.Type == "cmd") {

				// execute a command
				fmt.Printf("executing command: %s\n", hr.Cmd)

				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()

				cl := strings.Split(hr.Cmd, " ")
				fmt.Printf("cl (%d): %q\n", len(cl), cl)

				var out bytes.Buffer
				var stderr bytes.Buffer

				// believe this, go wants you to write an assembler bus width to execute commands with different numbers of arguments
				if (len(cl) == 1) {

					cmd := exec.CommandContext(ctx, cl[0])

					cmd.Stdout = &out
					cmd.Stderr = &stderr
					cmd.Run()

				} else if (len(cl) == 2) {

					cmd := exec.CommandContext(ctx, cl[0], cl[1])

					cmd.Stdout = &out
					cmd.Stderr = &stderr
					cmd.Run()

				} else if (len(cl) == 3) {

					cmd := exec.CommandContext(ctx, cl[0], cl[1], cl[2])

					cmd.Stdout = &out
					cmd.Stderr = &stderr
					cmd.Run()

				} else if (len(cl) == 4) {

					cmd := exec.CommandContext(ctx, cl[0], cl[1], cl[2], cl[3])

					cmd.Stdout = &out
					cmd.Stderr = &stderr
					cmd.Run()

				} else if (len(cl) == 5) {

					cmd := exec.CommandContext(ctx, cl[0], cl[1], cl[2], cl[3], cl[4])

					cmd.Stdout = &out
					cmd.Stderr = &stderr
					cmd.Run()

				} else if (len(cl) == 6) {

					cmd := exec.CommandContext(ctx, cl[0], cl[1], cl[2], cl[3], cl[4], cl[5])

					cmd.Stdout = &out
					cmd.Stderr = &stderr
					cmd.Run()

				} else if (len(cl) == 7) {

					cmd := exec.CommandContext(ctx, cl[0], cl[1], cl[2], cl[3], cl[4], cl[5], cl[6])

					cmd.Stdout = &out
					cmd.Stderr = &stderr
					cmd.Run()

				} else if (len(cl) == 8) {

					cmd := exec.CommandContext(ctx, cl[0], cl[1], cl[2], cl[3], cl[4], cl[5], cl[6], cl[7])

					cmd.Stdout = &out
					cmd.Stderr = &stderr
					cmd.Run()

				} else {
					stderr.Write([]byte("Go cannot handle more than some number of arguments to a command, try fewer.  The maximum for the ispapp-go-client is 7.  Won't be long before token bugs arrive to make sure you can properly parse ' and \" while escaping!"))
				}

				//fmt.Printf("command result: %s\n", out.String())

				// return {type: "cmd", "uuidv4": _, "stdout": "b64()", "stderr": "b64()", "ws_id": _}
				cmd_r := fmt.Sprintf("{\"type\": \"cmd\", \"uuidv4\": \"%s\", \"stdout\": \"%s\", \"stderr\": \"%s\", \"ws_id\": \"%s\"}", hr.UuidV4, b64.StdEncoding.EncodeToString(out.Bytes()), b64.StdEncoding.EncodeToString(stderr.Bytes()), hr.Ws_Id)

				err = c.WriteMessage(websocket.TextMessage, []byte(cmd_r))
				if err != nil {
					fmt.Println("error sending cmd response for " + host.Login + ":", err)
				} else {
					fmt.Println("sent cmd response for " + host.Login)
				}

			} else if (hr.UpdateFast) {
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

				// create a counter collector
				cols.Counter = make([]Counter, 4)

				// add tcp cwr
				var c0 Counter = Counter{}
				c0.Name = "TCP CWR Packets"
				c0.Point = host.CwrC
				cols.Counter[0] = c0

				// add tcp ece
				var c1 Counter = Counter{}
				c1.Name = "TCP ECE Packets"
				c1.Point = host.EceC
				cols.Counter[1] = c1

				// add tcp rst
				var c2 Counter = Counter{}
				c2.Name = "TCP RST Packets"
				c2.Point = host.RstC
				cols.Counter[2] = c2

				// add tcp syn
				var c3 Counter = Counter{}
				c3.Name = "TCP SYN Packets"
				c3.Point = host.SynC
				cols.Counter[3] = c3

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
				//fmt.Printf("host: %+v\n", host)

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

func pcap_routine(host *Host) {

	// don't forget this, if Apple ever fixes it in MacOS
	// func (p *InactiveHandle) SetRFMon(monitor bool) error

	// wait for host.WanIfName to be set
	for {

		fmt.Printf("Waiting for WAN Interface Name to be set.\n")
		time.Sleep(5 * time.Second)

		if (host.WanIfName != "") {
			break
		}
	}

	// capture live traffic on an interface, third option is for promiscuous mode
	handle, err := pcap.OpenLive(host.WanIfName, 1600, false, pcap.BlockForever)

	if (err != nil) {
		panic(err)
	}

	// 802.11 monitor mode does not work on MacOS 12
	// it does not work in Wireshark either
	// as there are no 802.11 frames to use for counting retransmits
	// we should set a filter to only capture TCP traffic so less resources are used
	filter_err := handle.SetBPFFilter("tcp")
	if (filter_err != nil) {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		// this shows all packet information
		//fmt.Printf("packet: %+v\n", packet)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			//fmt.Printf("TCP from src port %d to dst port %d with RST: %t and len(%d)\n", tcp.SrcPort, tcp.DstPort, tcp.RST, len(tcp.Payload))

			// loop through the map of all counted ports and increment those that are counted

			// count special bits
			// CWR - packet may have been modified in response to network congestion
			// ECE - for the first packet in a sequence, peer is ECN capable, the rest of the packets use it to indicate network congestion
			// RST - reset requested
			// SYN - indicates that this is the first packet in a sequence, a reconnect would reset this and it would be prevelant if 10 reconnects each only sent 20% of the data before all the data was sent on the 11th reconnect

			/*
			CWR (1 bit): Congestion window reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism.[b]
			ECE (1 bit): ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
			If the SYN flag is set (1), that the TCP peer is ECN capable.
			If the SYN flag is clear (0), that a packet with Congestion Experienced flag set (ECN=11) in the IP header was received during normal transmission.[b] This serves as an indication of network congestion (or impending congestion) to the TCP sender.
			*/

			// could also count the packet length and store the counts of [0-500], [501-1000], [1000-max]

			if (tcp.CWR) {
				host.CwrC += 1;
			}
			if (tcp.ECE) {
				host.EceC += 1;
			}
			if (tcp.RST) {
				host.RstC += 1;
			}
			if (tcp.SYN) {
				host.SynC += 1;
			}

		}

	}

}

func main() {

fmt.Println("USAGE:")
fmt.Println("\t./ispapp-go-client -domain \"dev.ispapp.co\" -hostKey \"yourhostkey\" -port 8550 -if \"en0\" -certPath \"/home/ec2-user/ispapp-keys/__ispapp_co.ca-bundle\"\n\n-port, -if and -certPath are not required.\n\n")

flag.StringVar(&domain, "domain", "unknown", "ISPApp domain")
flag.StringVar(&hostKey, "hostKey", "", "ISPApp Host Key")
flag.IntVar(&port, "port", 8550, "ISPApp port")
flag.StringVar(&loginInterface, "if", "", "Name of Interface for Login MAC Address")
flag.StringVar(&pemFile, "certPath", "/home/ec2-user/ispapp-keys/__ispapp_co.ca-bundle", "TLS certificate file path")

flag.Parse()

if (domain == "unknown") {
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

	// start pcap listening
	go pcap_routine(&h1)

	// create a socket to the listener
	go new_websocket(&h1)

	for {

		select {
			// wait for interrupt
		case <-interrupt:
			fmt.Println("close")
			os.Exit(0)
		}

	}

}
