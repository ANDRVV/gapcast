package main

import (
	"flag"
	"fmt"
	"gapcast/libs"
	"gapcast/libs/injpacket"
	"gapcast/libs/jsonreader"
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
	bettercap "github.com/bettercap/bettercap/packets"
	"github.com/eiannone/keyboard"
	colo "github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/rodaine/table"
	"golang.design/x/hotkey"
	"golang.org/x/exp/maps"
)

var (
	oldmoment            bool                         = true
	G5                   bool                         = false
	enabledWriter        bool                         = false
	panicExit            bool                         = false
	singleChannel        bool                         = false
	paused               bool                         = false
	stopScan             bool                         = false
	writing              bool                         = false
	rssiradar            bool                         = false
	openTable            bool                         = false
	injection            bool                         = false
	injblock             bool                         = false
	alreadyDKeyReg       bool                         = false
	sngtrgLoading        bool                         = false
	tdaPresent           bool                         = false
	rdaPresent           bool                         = false
	pddPresent           bool                         = false
	mt                   chan bool                    = make(chan bool)
	mtLoading            chan bool                    = make(chan bool)
	exitChannel          chan bool                    = make(chan bool)
	chanstage            chan bool                    = make(chan bool)
	inactiveClient       map[string]libs.DeviceClient = make(map[string]libs.DeviceClient)
	inactiveDevice       map[string]libs.Device       = make(map[string]libs.Device)
	mutex                sync.RWMutex                 = sync.RWMutex{}
	analysisData         *libs.Alldata                = new(libs.Alldata)
	globalChannel        int
	tableScene           int
	errTable             int
	txdbiAnt             float64
	rxdbiAnt             float64
	pwrdbmDevice         float64
	chTable              string
	srcTable             string
	dstTable             string
	esdTable             string
	capturedEapol        []string
	macFilter            string
	handle               *pcap.Handle
	color                libs.Colors
	elapsedTime          time.Time
	chartBSSID           table.Table
	chartCLIENT          table.Table
	macdb                []jsonreader.Macdb
	pcapWriter           *pcapgo.Writer
	pcapFile             *os.File
	tableinj             libs.INJTable
	seqdatalist          []libs.InjectData
	regDKey              *hotkey.Hotkey
	radarconf            jsonreader.RadarConf
)

func collect() ([]int, string, string, string, bool, string, bool, bool, string) {
	var ch *string = flag.String("c", "-1", "")
	var load *string = flag.String("l", "?", "")
	var bssid *string = flag.String("b", "?", "")
	var prefix *string = flag.String("p", "?", "")
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
	var showi *bool = flag.Bool("show-i", false, "")
	var nmrestart *bool = flag.Bool("nm-restart", false, "")
	var sc *string = flag.String("sc", "?", "")

	flag.Usage = func() {
		fmt.Println("Usage of gapcast:")
		fmt.Println()
		fmt.Println("Interfaces & band misc:")
		fmt.Println("   -show-i")
		fmt.Println("        Shows available network interfaces.")
		fmt.Println("   -i <interface> : string")
		fmt.Println("        Select network interface.")
		fmt.Println("   -5g")
		fmt.Println("        Start with 5 Ghz band.")
		fmt.Println("   -2.4+5g")
		fmt.Println("        Start with 2.4/5 Ghz band.")
		fmt.Println("   -nm-restart")
		fmt.Println("        Restart Network Manager. (Only for Linux)")
		fmt.Println()
		fmt.Println("Filter misc:")
		fmt.Println("   -c <channel> : int")
		fmt.Println("   -c <channels> : int,int,int...")
		fmt.Println("        Select working channel.")
		fmt.Println("   -b <BSSID> : string")
		fmt.Println("        Select BSSID filter.")
		fmt.Println("   -p <BSSID PREFIX> : string")
		fmt.Println("        Select BSSID prefix filter.")
		fmt.Println("   -beacon")
		fmt.Println("        Shows only beacons.")
		fmt.Println("   -d")
		fmt.Println("        Disable inactive devices hider.")
		fmt.Println("   -radar")
		fmt.Println("        Enable RadarRSSI.")
		fmt.Println()
		fmt.Println("Work with pcap:")
		fmt.Println("    -w <file>.pcap")
		fmt.Println("        Write to pcap file.")
		fmt.Println("    -l <file>.pcap")
		fmt.Println("        Load pcap file.")
		fmt.Println()
		fmt.Println("Features:")
		fmt.Println("    -sc <BSSID> : string")
		fmt.Println("        Scan a single target carefully.")
		fmt.Println()
		fmt.Println("Radar misc:")
		fmt.Println("    -dbi-tx <int (or float)>")
		fmt.Println("        Set TX antenna dBi.")
		fmt.Println("    -dbi-rx <int (or float)>")
		fmt.Println("        Set RX antenna dBi.")
		fmt.Println("    -dbm <int (or float)>")
		fmt.Println("        Set TX power.")
		os.Exit(1)
	}

	flag.Parse()

	if *showi {
		if libs.RootCheck() {
			if runtime.GOOS == "windows" {
				fmt.Println("HW-ADDR               NAME")
				for _, iface := range libs.ShowIfaces() {
					fmt.Println(iface.Name + "     " + iface.Mac)
				}
			} else {
				var writer *tabwriter.Writer = tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
				fmt.Fprintln(writer, "Interface\tHW-ADDR\tMode\tChannel\tTXpower\tDriver\tChipset")
				var exist int = 0
				for _, iface := range libs.ShowIfaces() {
					ifaceinfo, err := libs.GetIfaceInfo(iface.Name) 
					if err {
						continue
					}
					fmt.Fprintln(writer, iface.Name + "\t" + iface.Mac + "\t" + ifaceinfo[0] + "\t" + ifaceinfo[1] + "\t" + ifaceinfo[2] + "\t" + ifaceinfo[3] + "\t" + ifaceinfo[4])
					exist++
				}
				if exist > 0 {
					writer.Flush()
				} else {
					fmt.Println("No valid interface found.")
				}
			}
		} else {
			fmt.Println("Unrooted.")
		}
		os.Exit(0)
	}

	if *nmrestart {
		if runtime.GOOS == "linux" {
			if libs.RootCheck() {
				var nmrestartSeq []string = []string{"service networking restart", "service NetworkManager restart"}
				for _, nmcmd := range nmrestartSeq {
					if _, err := libs.Rtexec(exec.Command("bash", "-c", nmcmd)); err {
						fmt.Println("Unable to restart Network Manager.")
						os.Exit(0)
					}
				}
				fmt.Println("Network Manager restarted successful.")
			} else {
				fmt.Println("Unrooted.")
			}
		} else {
			fmt.Println("Valid parameter for only Linux system.")
		}
		os.Exit(0)
	}

	if *sc != "?" {
		if !libs.IsValidMAC(*sc) {
			fmt.Println("Mac address " + *sc + " is invalid (-sc).\n")
			flag.Usage()
		}
	}

	if *iface == "?" && *load == "?" {
		fmt.Println("Select an interface. If you want to see the available interfaces add -show-i parameter.")
		fmt.Println()
		flag.Usage()
	}

	if *g5 && *g5g24 {
		fmt.Println("You can't add both -5g and -2.4+5g, you have to select only one.")
		fmt.Println()
		flag.Usage()
	}

	var lencount int = 0
	var loadScan bool = false
	if *ch != "-1" {
		lencount += 2
	}
	if *bssid != "?" {
		lencount += 2
	}
	if *write != "?" {
		lencount += 2
	}
	if *iface != "?" {
		lencount += 2
	}
	if *prefix != "?" {
		lencount += 2
	}
	if *prefix != "?" && *bssid != "?" {
		fmt.Println("You can't add both -p and -b, -p don't work if bssid is specified.")
		fmt.Println()
		flag.Usage()
	}
	if *g5 {
		lencount++
	}
	if *g5g24 {
		lencount++
	}
	if *dinac {
		lencount++
	}
	if *radar {
		lencount++
	}
	if *beacon {
		lencount++
	}
	if *load != "?" {
		lencount += 2
	}
	if *sc != "?" {
		lencount += 2
	}
	var errc error
	if *txdbi != "?" {
		if txdbiAnt, errc = strconv.ParseFloat(*txdbi, 64); errc != nil {
			fmt.Println("TX dBi " + *txdbi + " is not int or float.\n")
			flag.Usage()
		}
		lencount += 2
		tdaPresent = true
	}
	if *rxdbi != "?" {
		if rxdbiAnt, errc = strconv.ParseFloat(*rxdbi, 64); errc != nil {
			fmt.Println("RX dBi " + *rxdbi + " is not int or float.\n")
			flag.Usage()
		}
		lencount += 2
		rdaPresent = true
	}
	if *pwrdbm != "?" {
		if pwrdbmDevice, errc = strconv.ParseFloat(*pwrdbm, 64); errc != nil {
			fmt.Println("TX Power " + *pwrdbm + " is not int or float.\n")
			flag.Usage()
		}
		lencount += 2
		pddPresent = true
	}

	if len(os.Args) - 1 > lencount {
		flag.Usage()
	}

	ChannelList, err := libs.ParseChannels(*ch, *g5, *g5g24)
	if err != "" {
		fmt.Println(err)
		fmt.Println()
		flag.Usage()
	}
	if !(ChannelList[0] != -1 && len(ChannelList) > 1) {
		singleChannel = true
	}

	if *bssid != "?" {
		if !libs.IsValidMAC(*bssid) {
			fmt.Println("Mac address " + *bssid + " is invalid.\n")
			flag.Usage()
		}
		if len(ChannelList) == 0 || len(ChannelList) > 1 {
			fmt.Println("Only one channel is needed if you use -b parameter.")
			fmt.Println()
			flag.Usage()
		}
	} else {
		*bssid = ""
	}

	macFilter = strings.ToLower(*bssid)
	G5 = *g5
	rssiradar = *radar

	if *load != "?" {
		if lencount >= 4 && *iface != "?" {
			loadScan = true
		} else if lencount > 2 {
			fmt.Println("If you have added the load parameter you cannot add other parameters if you don't specified the interface.")
			fmt.Println()
			flag.Usage()
		} 
	}

	return ChannelList, *write, *iface, strings.ToLower(*prefix), *dinac, *load, loadScan, *beacon, *sc
}

func signalExit(nameiface string, oldmoment bool) {
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
	go libs.Loading("[" + color.Blue + "EXIT" + color.White + "] Setting up managed mode", mtLoading)
	libs.SetManagedMode(nameiface)
	time.Sleep(1200 * time.Millisecond)
	mtLoading <- true
	time.Sleep(800 * time.Millisecond)
	for writing {time.Sleep(100 * time.Millisecond)}
}

func startSignal(nameiface string) {
	var regKey *hotkey.Hotkey = hotkey.New([]hotkey.Modifier{hotkey.ModCtrl}, hotkey.KeyC)
	regKey.Register()
	defer regKey.Unregister()
	for {
		<- regKey.Keydown()
		<- regKey.Keyup()
		injection = false
		openTable = false
		time.Sleep(100 * time.Millisecond)
		panicExit = true
		keyboard.Close()
		time.Sleep(600 * time.Millisecond)
		signalExit(nameiface, oldmoment)
	}
}

func setup(file string, nameiface string, load bool, pcapfile string) string {
	var iface string = libs.GetIfaceFromName(nameiface)
	if iface == "" {
		fmt.Println()
		libs.SignalError(color, "Bad interface, if you want to see the available interfaces add -show-i parameter.")
	}
	go startSignal(nameiface)
	libs.ScreenClear()
	if libs.WriterCheck(file) {
		enabledWriter = true
		pcapFile, err := os.Create(file)
		if err != nil {
			pcapFile.Close()
			fmt.Println("Invalid directory or file.")
			fmt.Println()
			os.Exit(1)
		}
		pcapWriter = pcapgo.NewWriter(pcapFile)
		pcapWriter.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio)
	}
	color = libs.SetupColors()
	libs.PrintLogo(color, "Initializing...")
	if !libs.AlreadyMon(nameiface) {
		if !libs.MonSupportCheck() {
			if runtime.GOOS == "windows" {
				libs.SignalError(color, "Npcap not installed.")
			} else {
				libs.SignalError(color, "Aircrack-ng not installed. (Needed Airmon-ng)")
			}
		}
		go libs.Loading("[" + color.Green + "INIT" + color.White + "] Setting up monitor mode", mt)
		if _, err := libs.SetMonitorMode(nameiface); err {
			mt <- true
			time.Sleep(400 * time.Millisecond)
			fmt.Println()
			libs.SignalError(color, "Bad interface or no administrator.")
		}
		time.Sleep(2 * time.Second)
		mt <- true
		mt = make(chan bool)
	} else {
		fmt.Println("[" + color.Green + "INIT" + color.White + "] Skipped (Monitor mode already enabled)")
		time.Sleep(1200 * time.Millisecond)
	}
	if G5 && !libs.G5Check(nameiface) {
		fmt.Println("\n[" + color.Red + "ERROR" + color.White + "] " + nameiface + " does not support 5 Ghz.")
		time.Sleep(600 * time.Millisecond)
		signalExit(nameiface, false)
	}
	go libs.Loading("[" + color.Green + "INIT" + color.White + "] Loading resources", mt)
	var warning1, warning2 bool = false, false
	macdb, warning1 = jsonreader.ReadMacdb()
	if rssiradar {
		if tdaPresent && rdaPresent && pddPresent {
			radarconf = jsonreader.RadarConf{TXAntennaDBI: txdbiAnt, RXAntennaDBI: rxdbiAnt, TXPowerDBM: pwrdbmDevice}
		} else {
			radarconf, warning2 = jsonreader.ReadRadarConf()
			if tdaPresent {
				radarconf.TXAntennaDBI = txdbiAnt
			}
			if rdaPresent {
				radarconf.RXAntennaDBI = rxdbiAnt
			}
			if pddPresent {
				radarconf.TXPowerDBM = pwrdbmDevice
			}
		}
	}
	setupChart()
	time.Sleep(1500 * time.Millisecond)
	mt <- true
	if load {
		mt = make(chan bool)
		go libs.Loading("[" + color.Green + "INIT" + color.White + "] Loading pcap file", mt)
		handle, err := pcap.OpenOffline(pcapfile)
		if err != nil {
			mt <- true
			fmt.Println("[" + color.Yellow + "WARNING" + color.White + "] No valid resources loaded.")
			time.Sleep(1200 * time.Millisecond)
		} else {
			defer handle.Close()
			handlePacket(handle, libs.G5g24Channels[:], "?", false, false, true)
			mt <- true
			if len(analysisData.DeviceData) <= 0 {
				fmt.Println("[" + color.Yellow + "WARNING" + color.White + "] No valid resources loaded.")
				time.Sleep(1200 * time.Millisecond)
			}
		}
	}
	if warning1 {
		fmt.Println("[" + color.Yellow + "WARNING" + color.White + "] Failure to read the manufacturer db.")
		time.Sleep(1200 * time.Millisecond)
	}
	if warning2 {
		if tdaPresent || rdaPresent || pddPresent {
			fmt.Println("[" + color.Yellow + "WARNING" + color.White + "] Failure to read RadioRSSI config, set default. (Applied with custom conf)")
		} else {
			fmt.Println("[" + color.Yellow + "WARNING" + color.White + "] Failure to read RadioRSSI config, set default.")
		}
		time.Sleep(1200 * time.Millisecond)
	}
	oldmoment = false
	time.Sleep(1 * time.Second)
	return iface
}

func ChannelChanger(ChannelList []int, nameiface string) {
	var changeCh func([]int, string) = func(ChannelList []int, nameiface string) {
		if singleChannel {
			libs.ChangeChannel(nameiface, ChannelList[0])
			globalChannel = ChannelList[0]
			time.Sleep(100 * time.Millisecond)
		} else {
			for {
				for _, ch := range ChannelList {
					select {
					case <- exitChannel:
						return
					default:
						for paused {time.Sleep(100 * time.Millisecond)}
						for injblock {time.Sleep(100 * time.Millisecond)}
						libs.ChangeChannel(nameiface, ch)
						mutex.Lock()
						globalChannel = ch
						mutex.Unlock()
						time.Sleep(130 * time.Millisecond)
					}
				}
			}
		}
	}
	if singleChannel {
		changeCh(ChannelList, nameiface)
	} else {
		go changeCh(ChannelList, nameiface)
	}
}

func update() { 
	var refreshTime time.Time = time.Now()
	if elapsedTime == (time.Time{}) {
		elapsedTime = time.Now()
	}
	var maxRefresh int64
	switch runtime.GOOS {
		case "windows":
			maxRefresh = 450
		default:
		 	maxRefresh = 20
	}
	for {
		time.Sleep(10 * time.Millisecond)
		if panicExit {
			exitChannel <- true
			for {time.Sleep(2 * time.Second)}
		}
		if int64(time.Since(refreshTime).Milliseconds()) > maxRefresh {
			printChart(false)
			time.Sleep(time.Millisecond * 5)
			refreshTime = time.Now()
		}
	}
}

func getChFromSaved(mac string) int {
	mac = strings.ToUpper(libs.Fmac(mac))
	if data, exist := analysisData.DeviceData[mac]; exist {
		return data.Ch
	} else if data, exist := inactiveDevice[mac]; exist {
		return data.Ch 
	}
	return -1
}

func sortForChannel(macs []string) []string {
	for i := 0; i < len(macs) - 1; i++ {
		for j := 0; j < len(macs) - i - 1; j++ {
			if getChFromSaved(macs[j]) > getChFromSaved(macs[j + 1]) {
				macs[j], macs[j + 1] = macs[j + 1], macs[j]
			}
		}
	}
	return macs
}

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
		sMac = tableinj.DST[0]
		sdtype = "src"
	} else {
		if injtype == "De-Auth" {
			mMac = sortForChannel(tableinj.DST)
		} else {
			mMac = tableinj.DST
		}
		sMac = tableinj.SRC[0]
		sdtype = "dst"
	}
	injblock = true
	mutex.Unlock()
	defer func(){injblock = false}()
	if len(mMac) > 2 {
		go func(){
			for {
				for _, m := range mMac {
					mutex.Lock()
					seqdatalist[len(seqdatalist) - 1].Target = injdst
					mutex.Unlock()
					time.Sleep(500 * time.Millisecond)
					if sdtype == "src" {
						injdst = sMac
					} else {
						injdst = m
					}
				}
				if !injection {return}
				for paused {time.Sleep(100 * time.Millisecond)}
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
						seqdatalist[len(seqdatalist) - 1].Of1++
					} else {
						seqdatalist[len(seqdatalist) - 1].Failed = true
					}
					time.Sleep(waitTime) 
					if !injection {return}
					for paused {time.Sleep(100 * time.Millisecond)}
				}	
			}
		} else if injtype == "De-Auth" {		
			seqdatalist = append(seqdatalist, libs.InjectData{Of1: 0, Of2: len(mMac), Target: injdst, Failed: false, Seq: "0"})
			if len(seqdatalist) == 1 {
				mutex.Lock()
				tableScene = 8
				mutex.Unlock()
			}
			var waitTime time.Duration = time.Duration(2 / len(mMac)) * time.Millisecond
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
					seqdatalist[len(seqdatalist) - 1].Target = injdst
				}
				for seq := 0; seq < 128; seq++ {
					seqdatalist[len(seqdatalist) - 1].Seq = libs.GetCapsFormat(strconv.Itoa(seq + 1), 3, "0") 
					if ptempl := injpacket.Deauth(injsrc, injdst, seq); !injpacket.InjectPacket(handle, nameiface, injch, prevch, ptempl) {
						seqdatalist[len(seqdatalist) - 1].Failed = true
					}
					time.Sleep(waitTime)
					if !injection {return}
					for paused {time.Sleep(100 * time.Millisecond)}
				}
				seqdatalist[len(seqdatalist) - 1].Of1++
			}
			time.Sleep(180 * time.Millisecond)
		}
	}
}

func regE(nameiface string) {
	var regKey *hotkey.Hotkey = hotkey.New([]hotkey.Modifier{hotkey.ModCtrl}, hotkey.KeyE)
	regKey.Register()
	defer regKey.Unregister()
	for {
		<- regKey.Keydown()
		<- regKey.Keyup()
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
}

func regD(nameiface string) {
	if !alreadyDKeyReg {
		regDKey = hotkey.New([]hotkey.Modifier{hotkey.ModCtrl}, hotkey.KeyD)
		alreadyDKeyReg = true
		regDKey.Register()
	}
	for {
		time.Sleep(100 * time.Millisecond)
		select {
			case <- regDKey.Keydown():
				<- regDKey.Keyup()
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

func regT(nameiface string, ChannelList []int) {
	var regKey *hotkey.Hotkey = hotkey.New([]hotkey.Modifier{hotkey.ModCtrl}, hotkey.KeyT)
	regKey.Register()
	defer regKey.Unregister()
	for {
		<- regKey.Keydown()
		<- regKey.Keyup()
		mutex.Lock()
		keyboard.Close()
		if !openTable {
			tableinj = libs.INJTable{}
			srcTable, dstTable, esdTable, tableScene, errTable = "", "", "", 0, 0
			openTable = true
			go regXINJ(nameiface, ChannelList)
		} else {
			openTable = false
			injection = false
		}
		mutex.Unlock()
	}
}

func regXINJ(nameiface string, ChannelList []int) {
	event, _ := keyboard.GetKeys(10)
	for {
		eventdata := <- event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if eventdata.Rune == '1' {
			tableinj = libs.INJTable{INJ: "De-Auth"}
			tableScene = 1
			keyboard.Close()
			go reg1234(nameiface, ChannelList)
			mutex.Unlock()
			return
		} else if eventdata.Rune == '2' {
			tableinj = libs.INJTable{INJ: "Beacon", DST: []string{"ffffffffffff"}}
			tableScene = 1
			keyboard.Close()
			go reg1234(nameiface, ChannelList)
			mutex.Unlock()
			return
		}
		mutex.Unlock()
	}
}

func regESSID(nameiface string) {
	event, _ := keyboard.GetKeys(10)
	for {
		eventdata := <- event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if eventdata.Key == keyboard.KeyBackspace && len(esdTable) > 0 {
			esdTable = esdTable[:len(esdTable) - 1]
			mutex.Unlock()
			continue
		}
		if eventdata.Key == keyboard.KeyEnter {
			if libs.IsValidESSID(esdTable) {
				tableinj.ESSID = esdTable
				tableScene = 7
				esdTable = ""
				keyboard.Close()
				go regD(nameiface)
			} else {
				var oldScene int = tableScene
				errTable = 1
				tableScene = 9
				mutex.Unlock()
				time.Sleep(3 * time.Second)
				mutex.Lock()
				tableScene = oldScene
				esdTable = ""
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

func regCh(nameiface string, ChannelList []int) {
	event, _ := keyboard.GetKeys(10)
	for {
		eventdata := <- event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if eventdata.Key == keyboard.KeyBackspace && len(chTable) > 0 {
			chTable = chTable[:len(chTable) - 1]
		}
		if eventdata.Key == keyboard.KeyEnter {
			ch, _ := strconv.Atoi(chTable)
			if slices.Contains(ChannelList, ch) {
				tableinj.CHANNEL = ch
				tableScene = 10
				chTable = ""
				keyboard.Close()
				go regESSID(nameiface)
			} else {
				var oldScene int = tableScene
				tableScene = 9
				errTable = 2
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

func reg1234(nameiface string, ChannelList []int) {
	event, _ := keyboard.GetKeys(10)
	for {
		eventdata := <- event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if eventdata.Rune == '1' {
			if tableScene == 1 {
				tableScene = 2
				keyboard.Close()
				go regWM("src", nameiface, ChannelList)
			} else if tableScene == 3 {
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
			} else if tableScene == 5 {
				tableScene = 1
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
			} else if tableScene == 6 {
				tableScene = 3
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
			}
			mutex.Unlock()
			return
		} else if eventdata.Rune == '2' {
			if tableScene == 1 {
				if tableinj.INJ == "De-Auth" {
					tableinj.SRC = libs.GetNoDuplicates(append(tableinj.SRC, maps.Keys(analysisData.DeviceData)...))
					tableScene = 5
					keyboard.Close()
					go reg1234(nameiface, ChannelList)
				} else if tableinj.INJ == "Beacon" {
					tableinj.SRC = libs.GetNoDuplicates(append(tableinj.SRC, libs.RandMac()))
					tableScene = 11
					keyboard.Close()
					go regCh(nameiface, ChannelList)
				}
			} else if tableScene == 3 {
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
			} else if tableScene == 5 {
				tableScene = 3
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
			} else if tableScene == 6 {
				tableScene = 7
				keyboard.Close()
				go regD(nameiface)
			}
			mutex.Unlock()
			return
		} else if eventdata.Rune == '3' {
			if tableScene == 3 {
				tableScene = 4
				keyboard.Close()
				go regWM("dst", nameiface, ChannelList)
			}
			mutex.Unlock()
			return
		} else if eventdata.Rune == '4' && tableinj.INJ == "De-Auth" && len(tableinj.SRC) == 1 {
			if stations := getStationsFromBSSIDs(tableinj.SRC); len(stations) > 0 {
				tableinj.DST = libs.GetNoDuplicates(append(tableinj.DST, stations...))
				tableScene = 6
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
			} else {
				var oldScene int = tableScene
				tableScene = 9
				errTable = 2
				mutex.Unlock()
				time.Sleep(3 * time.Second)
				mutex.Lock()
				tableScene = oldScene
				keyboard.Close()
				go reg1234(nameiface, ChannelList)
			}
			mutex.Unlock()
			return
		}
		mutex.Unlock()
	}
}

func regWM(way string, nameiface string, ChannelList []int) {
	event, _ := keyboard.GetKeys(10)
	for openTable {
		eventdata := <- event
		mutex.Lock()
		if eventdata.Key == keyboard.KeyEsc {
			openTable = false
			keyboard.Close()
			mutex.Unlock()
			return
		}
		if eventdata.Key == keyboard.KeyBackspace {
			if way == "src" && len(srcTable) > 0 { 
				srcTable = srcTable[:len(srcTable) - 1]
			} else if way == "dst" && len(dstTable) > 0 {
				dstTable = dstTable[:len(dstTable) - 1]
			}
		}
		if strings.Contains("abcdefABCDEF1234567890", fmt.Sprintf("%c", eventdata.Rune)) {
			if way == "src" {
				srcTable += strings.ToUpper(fmt.Sprintf("%c", eventdata.Rune))
				if len(srcTable) >= 12 {
					if tableinj.INJ == "De-Auth" {
						if getChFromSaved(srcTable) != -1 {
							tableinj.SRC = libs.GetNoDuplicates(append(tableinj.SRC, srcTable))
							srcTable = ""
							tableScene = 5
							keyboard.Close()
							go reg1234(nameiface, ChannelList)
						} else {
							var oldScene int = tableScene
							tableScene = 9
							errTable = 1
							mutex.Unlock()
							time.Sleep(3 * time.Second)
							mutex.Lock()
							tableScene = oldScene
							srcTable = ""
							keyboard.Close()
							go regWM("src", nameiface, ChannelList)
						}
					} else if tableinj.INJ == "Beacon" {
						tableinj.SRC = libs.GetNoDuplicates(append(tableinj.SRC, srcTable))
						srcTable = ""
						tableScene = 11
						keyboard.Close()
						go regCh(nameiface, ChannelList)
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

func moveActiveToInactive() {
	for {
		time.Sleep(100 * time.Millisecond)
		if paused || panicExit {return}
		if injblock {for {time.Sleep(100 * time.Millisecond); if !injblock {resetPreActive(); break}}}
		mutex.Lock()
		for mac, devices := range analysisData.ClientData {
			if time.Since(devices.LastUpdate) > time.Second * 30 {
				delete(analysisData.ClientData, mac)
				inactiveClient[mac] = devices
			}
		}
		for bssid, devices := range analysisData.DeviceData {
			if time.Since(devices.LastUpdate) > time.Second * 30 {
				delete(analysisData.DeviceData, bssid)
				inactiveDevice[bssid] = devices
			}
		}
		mutex.Unlock()
	}
}

func recEapol(packet gopacket.Packet) {
	if packet.Layer(layers.LayerTypeDot11) != nil {
		if exist, _, apmac, stamac := bettercap.Dot11ParseEAPOL(packet, packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)); exist {
			if libs.IsValidMAC(apmac.String()) && libs.IsValidMAC(stamac.String()) && !slices.Contains(capturedEapol, apmac.String() + "<-" + stamac.String()){
				capturedEapol = append(capturedEapol, apmac.String() + "<-" + stamac.String())
			}
		}
	}
	if packet.Layer(layers.LayerTypeEAPOLKey) != nil {
		mutex.Lock()
		writeToPcap(packet)
		mutex.Unlock()
	}
}

func writeToPcap(packet gopacket.Packet) {
	if enabledWriter && !panicExit {
		writing = true
		pcapWriter.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		Length:         len(packet.Data()),
		CaptureLength: len(packet.Data()), 
		}, packet.Data())
		writing = false
	}
}

func handlePacket(handle *pcap.Handle, chans []int, prefix string, filter bool, onlyBeacon bool, offload bool) {
	var packets *gopacket.PacketSource = gopacket.NewPacketSource(handle, handle.LinkType())
	defer handle.Close()

	var firstMP, lastMP time.Time
	if offload {defer func(){elapsedTime = time.Now().Add(-lastMP.Sub(firstMP))}()}
	
	for pkt := range packets.Packets() {
		if paused || panicExit || stopScan {return}
		if offload {
			lastMP = pkt.Metadata().Timestamp
			if firstMP.IsZero() {
				firstMP = pkt.Metadata().Timestamp
			}
		}
		go recEapol(pkt)
		go func(packet gopacket.Packet) {
			if packet.ErrorLayer() == nil && packet != nil && packet.Layer(layers.LayerTypeDot11) != nil {
				if PWR, err := libs.GetDBM(packet); !err {
					if libs.IsBeacon(packet) {
						if SRC, err1 := libs.GetSRCBeacon(packet); err1 == nil {
							if filter && ((macFilter != "" && !strings.EqualFold(macFilter, SRC)) || (prefix != "?" && !strings.HasPrefix(strings.ToLower(SRC), strings.ToLower(prefix)))) {return}
							exist1, ENC := libs.GetEncString(bettercap.Dot11ParseEncryption(packet, packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)))
							exist2, Channel := bettercap.Dot11ParseDSSet(packet)
							if exist2 && Channel > 0 && slices.Contains(chans, Channel) {
								if filter && singleChannel && Channel != globalChannel {return}
								var oldBeacon, oldData int = 0, 0
								var MANUFTR string
								exist, ESSID := bettercap.Dot11ParseIDSSID(packet)
								if !exist || !libs.IsValidESSID(ESSID) {
									ESSID = "<?>"
								}
								mutex.Lock()
								if _, exist3 := analysisData.DeviceData[SRC]; exist3 {
									oldBeacon = analysisData.DeviceData[SRC].Beacons
									oldData = analysisData.DeviceData[SRC].Data
									if (!libs.IsValid(ESSID) || ESSID == "<?>") && analysisData.DeviceData[SRC].Essid != ESSID {
										ESSID = analysisData.DeviceData[SRC].Essid
									}
									if !exist1 {
										ENC = analysisData.DeviceData[SRC].Enc
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
					} else if BSSID_CLIENT, MAC, err := libs.GetAPSTDATA(packet); bettercap.Dot11IsDataFor(packet.Layer(layers.LayerTypeDot11).(*layers.Dot11), libs.ParseMac(MAC)) && err == nil && !onlyBeacon {
						if filter {
							if strings.EqualFold(BSSID_CLIENT, MAC) || strings.EqualFold(MAC, "ff:ff:ff:ff:ff:ff") || (macFilter != "" && !strings.EqualFold(macFilter, BSSID_CLIENT)) {
								return
							}
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
			}
		} (pkt)
	}
}

func handlehandle(nameiface string, iface string, chans []int, prefix string, dinac bool, onlyBeacon bool) {
	handle = libs.GetMonitorSniffer(nameiface, iface, color)
	go handlePacket(handle, chans, prefix, true, onlyBeacon, false)
	if !dinac {
		go moveActiveToInactive()
	}
	for {
		time.Sleep(time.Millisecond * 100)
		if paused {
			for {
				time.Sleep(time.Millisecond * 100)
				if !paused {
					if !dinac {
						resetPreActive()
					}
					handle = libs.GetMonitorSniffer(nameiface, iface, color)
					go handlePacket(handle, chans, prefix, true, onlyBeacon, false)
					if !dinac {
						go moveActiveToInactive()
					}
					break
				}
			}
		}
	}
}

func engine(nameiface string, iface string, ChannelList []int, prefix string, dinac bool, onlyBeacon bool) {
	ChannelChanger(ChannelList, nameiface)
	go handlehandle(nameiface, iface, ChannelList, prefix, dinac, onlyBeacon)
	go regE(nameiface)
	go regT(nameiface, ChannelList)
	update()
}

func printChart(offline bool) {
	var deviceDataSort []string
	var clientDataSort []string
	mutex.Lock()
	for bssid := range analysisData.DeviceData {
		deviceDataSort = append(deviceDataSort, bssid)
	}
	sort.Strings(deviceDataSort)
	for _, bssid := range deviceDataSort {
		if rssiradar {
			chartBSSID.AddRow(bssid, analysisData.DeviceData[bssid].Enc + " ", analysisData.DeviceData[bssid].Power, analysisData.DeviceData[bssid].Beacons, analysisData.DeviceData[bssid].Data, analysisData.DeviceData[bssid].Ch, analysisData.DeviceData[bssid].Essid, analysisData.DeviceData[bssid].Manufacturer, libs.RadioLocalize(analysisData.DeviceData[bssid].Power, analysisData.DeviceData[bssid].Ch, radarconf))
		} else {
			chartBSSID.AddRow(bssid, analysisData.DeviceData[bssid].Enc + " ", analysisData.DeviceData[bssid].Power, analysisData.DeviceData[bssid].Beacons, analysisData.DeviceData[bssid].Data, analysisData.DeviceData[bssid].Ch, analysisData.DeviceData[bssid].Essid, analysisData.DeviceData[bssid].Manufacturer)
		}
	}
	for mac := range analysisData.ClientData {
		clientDataSort = append(clientDataSort, mac)
	}
	sort.Strings(clientDataSort)
	for _, mac := range clientDataSort {
		if rssiradar {
			chartCLIENT.AddRow(mac, analysisData.ClientData[mac].Bssid, analysisData.ClientData[mac].Power, analysisData.ClientData[mac].Data, analysisData.ClientData[mac].Essid, analysisData.ClientData[mac].Manufacturer, libs.RadioLocalize(analysisData.ClientData[mac].Power, analysisData.DeviceData[strings.ToLower(analysisData.ClientData[mac].Bssid)].Ch, radarconf))
		} else {
			chartCLIENT.AddRow(mac, analysisData.ClientData[mac].Bssid, analysisData.ClientData[mac].Power, analysisData.ClientData[mac].Data, analysisData.ClientData[mac].Essid, analysisData.ClientData[mac].Manufacturer)
		}
	}
	mutex.Unlock()
	libs.ScreenClear()
	fmt.Print(libs.GetRow1(color, capturedEapol, globalChannel, elapsedTime, offline))
	chartBSSID.Print()
	fmt.Println()
	if len(analysisData.ClientData) != 0 {
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
		for paused {time.Sleep(100 * time.Millisecond)}
		elapsedTime = elapsedTime.Add(time.Until(elapsedTimePause))
	}
}

func setupChart() {
	if rssiradar {
		chartBSSID = table.New("BSSID", "ENC", "PWR", "BEACONS", "DATA", "CH", "ESSID", "MANUFACTURER", "RAY")
	} else {
		chartBSSID = table.New("BSSID", "ENC", "PWR", "BEACONS", "DATA", "CH", "ESSID", "MANUFACTURER")
	}
	chartBSSID.WithHeaderFormatter(colo.New(colo.BgHiBlue, colo.FgHiWhite).SprintfFunc())
	if rssiradar {
		chartCLIENT = table.New("STATION", "BSSID", "PWR", "DATA", "ESSID", "MANUFACTURER", "RAY")
	} else {
		chartCLIENT = table.New("STATION", "BSSID", "PWR", "DATA", "ESSID", "MANUFACTURER")
	}
	chartCLIENT.WithHeaderFormatter(colo.New(colo.BgHiCyan, colo.FgHiWhite).SprintfFunc())
	analysisData.DeviceData = make(map[string]libs.Device)
	analysisData.ClientData = make(map[string]libs.DeviceClient)
}

func loaderSetupView(file string) {
	libs.ScreenClear()
	color = libs.SetupColors()
	libs.PrintLogo(color, "Initializing...")
	go libs.Loading("[" + color.Green + "INIT" + color.White + "] Loading pcap file", mt)
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
	setupChart()
	if warning {
		fmt.Println("[" + color.Yellow + "WARNING" + color.White + "] Failure to read the manufacturer db.")
		time.Sleep(1200 * time.Millisecond)
	}
	handlePacket(handle, libs.G5g24Channels[:], "?", false, false, true)
	if len(analysisData.DeviceData) <= 0 {
		mt <- true
		fmt.Println()
		libs.SignalError(color, "No valid resources loaded.")
	}
	time.Sleep(1200 * time.Millisecond)
	mt <- true
	time.Sleep(1 * time.Second)
}

func deepScanning(ChannelList []int, nameiface string, iface string, bssid string) {
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
			libs.ScreenClear()
			libs.PrintLogo(color, "Running scan mode...")
			fmt.Println(color.White + "[" + color.Blue + "MSG" + color.White + "] Gapcast's target scanner")
			fmt.Println()
			time.Sleep(2 * time.Second)
		}
		if stage != 4 {
			go libs.Loading(color.White + "[" + color.Green + "SCAN" + color.White + "] Stage " + strconv.Itoa(stage) + " <" + color.Purple + stagemsg[stage - 1] + color.White + ">", chanstage)
		}
		time.Sleep(1 * time.Second)
		switch stage {
			case 1:
				ChannelChanger(ChannelList, nameiface)
				handle = libs.GetMonitorSniffer(nameiface, iface, color)
				go handlePacket(handle, ChannelList, "?", false, false, false)
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
				stopScan = true
				chanstage <- true
			case 2:
				var handle *pcap.Handle = libs.GetMonitorSniffer(nameiface, iface, color)
				var packets *gopacket.PacketSource = gopacket.NewPacketSource(handle, handle.LinkType())
				defer handle.Close()
				singleChannel = true
				ChannelChanger([]int{info.Channel}, nameiface)
				var scantime time.Time = time.Now()
				for packet := range packets.Packets() {
					if packet.ErrorLayer() == nil && packet != nil && packet.Layer(layers.LayerTypeDot11) != nil {
						if PWR, err := libs.GetDBM(packet); !err {
							if TRS, RCV, err := libs.GetAPSTDATA(packet); err == nil {
								if strings.EqualFold(RCV, srcmac) {									
									info.ReceivedPKT++					
								} else if strings.EqualFold(TRS, srcmac) {
									dbmreg = append(dbmreg, int(PWR))
									info.SendedPKT++
								}
								if dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11); 
								dot11.Type.MainType() == layers.Dot11TypeCtrl {
									info.SndRcvACK++
								}
							}
						}
					}
					if int64(time.Since(scantime).Seconds()) > 10 {
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
				if len(dbmreg) % 2 == 0 {
					deviceDBM = (dbmreg[drlen - 1] + dbmreg[drlen]) / 2
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
	fmt.Println("\n" + color.White + "Analysis's response")
	fmt.Println(color.White + ">  =========================\n")
	fmt.Println(color.White + "     | [" + color.Blue + "ESSID" + color.White + "]       " + info.Essid)
	var spcsForNames []int = []int{6, 4, 5, 1, 1, 8, 1, 3, 3, 3}
	var infonames []string = []string{"BSSID", "CHANNEL", "VENDOR", "SENDED-PKT", "RECEVD-PKT", "ACK", "RECEVD-DBM", "ANT-2DBI", "ANT-3DBI", "ANT-5DBI"}
	for idxname, infoelem := range []interface{}{srcmac, 
		                                         info.Channel,
												 info.Manufacturer, 
												 info.SendedPKT,
												 info.ReceivedPKT, 
												 info.SndRcvACK,
												 strconv.Itoa(deviceDBM) + " dBm", 
												 info.PowerLOW, 
												 info.PowerMID, 
												 info.PowerHIGH} {
		fmt.Printf("%s %v\n", color.White + "     | [" + color.Blue + infonames[idxname] + color.White + "]" + strings.Repeat(" ", spcsForNames[idxname]), infoelem)
	}
	var deviceType string
	switch isClient {
		case true:
			deviceType = "STATION"
		case false:
			deviceType = "ACCESS-POINT"
	}
	if tdaPresent || rdaPresent || pddPresent {
		fmt.Println(color.White + "     | [" + color.Blue + "CUSTM-CONF" + color.White + "]  " + libs.RadioLocalize(deviceDBM, info.Channel, customRadarconf))
	}
	fmt.Println(color.White + "     | [" + color.Blue + "DEVICE-TYPE" + color.White + "] " + deviceType)
	fmt.Println("\n" + color.White + "   =========================")
}


func main() {
	ChannelList, file, nameiface, prefix, disableInactiver, loaderFile, loadScan, onlyBeacon, scbssid := collect()
	if scbssid != "?" {
		rssiradar = true
		deepScanning(ChannelList, nameiface, setup("?", nameiface, false, ""), scbssid)
	} else if loaderFile == "?" {
		engine(nameiface, setup(file, nameiface, false, ""), ChannelList, prefix, disableInactiver, onlyBeacon)
	} else if libs.ReaderCheck(loaderFile) {
		if loadScan {
			engine(nameiface, setup(file, nameiface, true, loaderFile), ChannelList, prefix, disableInactiver, onlyBeacon)
		} else {
			loaderSetupView(loaderFile)
			printChart(true)
		}
	}
}