package libs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"gapcast/libs/RadarRSSI"
	"gapcast/libs/RadarRSSI/libs"
	"gapcast/libs/jsonreader"
	"gapcast/libs/mon"
	color2 "github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mattn/go-isatty"
	"golang.org/x/exp/slices"
)

var (
	// in order by coverage signal
	G24channels []int = []int{
		/* Band group 1 */ 1, 6, 11,
		/* Band group 2 */ 2, 7, 12,
		/* Band group 3 */ 3, 8, 13,
		/*              */ 4, 9, 14,
		/*              */ 5, 10,
	}

	// in descending order by coverage signal (20, 40, 80, 160 MHz)
	G5channels []int = []int{
		/* 160 MHz coverage */ 50, 114, 163,
		/*  80 MHz coverage */ 42, 58, 106, 122, 138, 155, 171,
		/*  40 MHz coverage */ 38, 46, 54, 62, 102, 110, 126, 134, 142, 159, 167, 175,
		/*  20 MHz coverage */ 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177,
	}

	G5g24Channels []int = []int(append(G24channels, G5channels...))
)

var (
	mtLoading              chan bool = make(chan bool)
	maxRetryMonitorSniffer int       = 10
	LAcode                 []string  = []string{"2", "6", "A", "E", "3", "7", "B", "F"}
)

const (
	VERSION string = "1.0.3"
)

// Clear terminal display
func ScreenClear() {
	var cmd *exec.Cmd = exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// Print gapcast usage
func PrintUsage() {
	text := `Usage of gapcast:
	
Interfaces & band misc:
   -show-i")
        Shows available network interfaces.
   -i <interface> : string
        Select network interface.
   -5g
        Start with 5 Ghz band.
   -2.4+5g
        Start with 2.4/5 Ghz band.
   -nm-restart
        Restart Network Manager and reset configs.

Filter misc:"
   -c <channel> : int"
   -c <channels> : int,int,int...
        Select working channel.
   -b <BSSID> : string"
        Select BSSID filter.
   -p <BSSID PREFIX> : string
        Select BSSID prefix filter.
   -beacon
        Shows only beacons.
   -enc <OPEN, WPE, WPA, WPA2, WPA3>
        Select encryption filter.
   -cipher <WEP, TKIP, WRAP, CCMP, WEP104, CMAC, GCMP,
            GCMP256, CCMP256, GMAC, GMAC256, CMAC256>
        Select cipher suite filter.
   -auth <MGT, PSK, FT/MGT256, FT/PSK, MGT256, PSK256,
          TDLS, SAE, FT/SAE, APPeerKey, MGT-B, MGT-CNSA, FT/MGT-384,
          FILS/MGT, FILS/MGT-384, FT/FILS-256, FT/FILS-384, FT/PSK-384, PSK-384>
        Select auth suite filter.
   -d
        Disable inactive devices hider.
   -radar
        Enable RadarRSSI.

Work with pcap:
    -w <file>.pcap
        Write to pcap file.
    -l <file>.pcap
        Load pcap file.

Features:
    -sc <BSSID> : string
        Scan a single target carefully.

Radar misc:
    -dbi-tx <int (or float)>
        Set TX antenna dBi.
    -dbi-rx <int (or float)>
        Set RX antenna dBi.
    -dbm <int (or float)>
        Set TX power.
`
	fmt.Println(text)
}

// Check selected channels
func ParseChannels(ch string, g5 bool, g5g24 bool) ([]int, string) {
	if ch == "-1" {
		switch true {
		case g5g24:
			return G5g24Channels[:], ""
		case g5:
			return G5channels[:], ""
		default:
			return G24channels[:], ""
		}
	}
	var channelList []int
	for _, channelStr := range strings.Split(ch, ",") {
		channel, err := strconv.Atoi(channelStr)
		if err == nil {
			if !g5g24 {
				if g5 {
					if !slices.Contains(G5channels[:], channel) {
						return nil, fmt.Sprintf("Channel %s is invalid for 5 GHz.", channelStr)
					} 
				} else {
					if !slices.Contains(G24channels[:], channel) {
						return nil, fmt.Sprintf("Channel %s is invalid for 2.4 GHz.", channelStr)
					}
				}
			}
		} else {
			return nil, fmt.Sprintf("Channel %s is invalid.", channelStr)
		}
		channelList = append(channelList, channel)
	}
	return channelList, ""
}

// Show network interfaces
func ShowIfaces() (ifaces []Ifaces) {
	devs, _ := net.Interfaces()
	var ifacelist []Ifaces
	for _, iface := range devs {
		if len(iface.HardwareAddr) > 0 {
			ifacelist = append(ifacelist, Ifaces{Name: iface.Name, Mac: iface.HardwareAddr.String()})
		}
	}
	return ifacelist
}

// Set managed mode on interface
func SetManagedMode(nameiface string) {
	if err := mon.SetMode(nameiface, mon.MANAGED); err {
		for _, iface := range ShowIfaces() {
			if strings.Contains(iface.Name, nameiface) { // run this code if iface is potentially managed by airmon-ng
				phyface, _ := Rtexec(exec.Command("bash", "-c", fmt.Sprintf("ls /sys/class/net/%s/device/ieee80211 | awk '{print $1}'", iface.Name)))
				Rtexec(exec.Command("bash", "-c", fmt.Sprintf("iw %s del", iface.Name)))
				Rtexec(exec.Command("bash", "-c", fmt.Sprintf("iw phy %s interface add %s type managed", phyface, nameiface)))
			}
		}
	}
}

// Set monitor mode on interface
func SetMonitorMode(nameiface string) (err bool) {
	Rtexec(exec.Command("bash", "-c", "airmon-ng check kill"))
	if err := mon.SetMode(nameiface, mon.MONITOR); err {
		return true
	}
	for _, ifaces := range ShowIfaces() {
		if fsiface, _ := strings.CutSuffix(ifaces.Name, "mon"); fsiface == nameiface && ifaces.Name != nameiface {
			if _, err = Rtexec(exec.Command("bash", "-c", fmt.Sprintf("ip link set %s name %s", ifaces.Name, nameiface))); !err {
				return false
			}

		}
	}
	for _, ifaces := range ShowIfaces() {
		if strings.Contains(ifaces.Name, nameiface) && ifaces.Name != nameiface {
			_, err = Rtexec(exec.Command("bash", "-c", fmt.Sprintf("ip link set %s name %s", ifaces.Name, nameiface)))
		}
	}
	return err
}

// Execute commands on OS shell
func Rtexec(cmd *exec.Cmd) (output string, err bool) {
	cmdoutput, err1 := cmd.CombinedOutput()
	if err1 != nil || strings.Contains(string(cmdoutput), "fail") {
		return string(cmdoutput), true
	}
	return string(cmdoutput), false
}

// Print loading msg
func Loading(msg string, mt chan bool) {
	var idx int = 0
	var spinner [4]string = [4]string{"|", "/", "-", "\\"}
	for {
		select {
		case <-mt:
			fmt.Printf("\r%s ... Done\n", msg)
			return
		default:
			fmt.Printf("\r%s [%s] ... ", msg, spinner[idx])
			idx = (idx + 1) % 4
			time.Sleep(120 * time.Millisecond)
		}
	}
}

// Setup color escapes
func SetupColors() (color Colors) {
	var noColor bool = (os.Getenv("NO_COLOR") != "") || os.Getenv("TERM") == "dumb" || (!isatty.IsTerminal(os.Stdout.Fd()))
	if !noColor {
		color2.White("")
	}
	if noColor {
		color = Colors{
			Red:       "",
			White:     "",
			Yellow:    "",
			Blue:      "",
			Purple:    "",
			Cyan:      "",
			Orange:    "",
			Green:     "",
			Lightblue: "",
			Null:      "",
		}
	} else {
		color = Colors{
			Red:       "\033[1;31m",
			White:     "\033[1;37m",
			Yellow:    "\033[38;5;227m",
			Blue:      "\033[1;34m",
			Purple:    "\033[1;35m",
			Cyan:      "\033[1;36m",
			Orange:    "\033[1;38;5;208m",
			Green:     "\033[1;32m",
			Lightblue: "\033[38;5;117",
			Null:      "\033[0m",
		}
	}
	fmt.Print(color.White)
	return color
}

// Print logo
func PrintLogo(color Colors, msg string) {
	ScreenClear()
	text := fmt.Sprintf(`%s
%s         :~7JJJJJ~      
%s       !G&@@@@@@@Y      
%s      ?@@@@B5JY55^      %s| 
%s     ^@@@@J             %s| %s
%s     5@@@B              %s| 
%s    .&@@@J              %s| Welcome to Gapcast!
%s    !@@@@~   .....      %s| Version %s
%s    Y@@@&.  .B&&&7      %s| 
%s    G@@@B   ~@@@@^      %s| github.com/ANDRVV/gapcast
%s   .#@@@5   ?@@@#.      %s| 
%s   :&@@@Y   P@@@P       %s| 
%s   .#@@@#^.:#@@@?       %s| 
%s    !&@@@@##@@@@~.      %s|            Andrea Vaccaro
%s     ^5B&&@&&&#G..      %s

`,
	color.Green,
	color.Green,
	color.Green,
	color.Green, color.Blue,
	color.Green, color.Blue, msg,
	color.Green, color.Blue,
	color.Green, color.Blue,
	color.Green, color.Blue, VERSION,
	color.Green, color.Blue,
	color.Green, color.Blue,
	color.Green, color.Blue,
	color.Green, color.Blue,
	color.Green, color.Blue,
	color.Green, color.Blue,
	color.Green, color.White)

	fmt.Print(text)
}

// Print an error msg and exit
func SignalError(color Colors, msg string) {
	defer os.Exit(1)
	Error(color, msg)
	time.Sleep(800 * time.Millisecond)
}

// Change current channel of interface
func ChangeChannel(nameiface string, channel int) {
	Rtexec(exec.Command("bash", "-c", fmt.Sprintf("iwconfig %s channel %d", nameiface, channel)))
}

// Convert MAC (string) to MAC (net.HardwareAddr)
func ParseMac(mac string) (hwAddr net.HardwareAddr) {
	hwAddr, _ = net.ParseMAC(mac)
	return
}

// Seconds to format model 00h00m00s
func SecondsToHMS(seconds int) (formattedTime string) {
	var hours int = seconds / 3600
	var minutes int = (seconds % 3600) / 60
	seconds = seconds % 60
	switch {
	case hours > 0:
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

// Radiolocalize a device from data and return meters (approximately)
func RadioLocalize(ReceivedDBM int, Channel int, radarconf jsonreader.RadarConf) (meters string) {
	var RxFData libs.RFData
	var TXData libs.TransmitterData
	if reflect.DeepEqual(radarconf, jsonreader.RadarConf{}) {
		RxFData = RadarRSSI.GetCustomRFData(float64(ReceivedDBM), Channel, 5)
		TXData = RadarRSSI.GetCustomTransmitterData(4, 17.5)
	} else {
		RxFData = RadarRSSI.GetCustomRFData(float64(ReceivedDBM), Channel, radarconf.RXAntennaDBI)
		TXData = RadarRSSI.GetCustomTransmitterData(radarconf.TXAntennaDBI, radarconf.TXPowerDBM)
	}
	return fmt.Sprintf("~%.1fm", RadarRSSI.Radiolocate(RxFData, TXData, RadarRSSI.GetAutoDBPathLoss(RxFData)))
}

// Get manufacturer (vendor) from mac address using a database
func GetManufacturer(macdb []jsonreader.Macdb, mac string) (manufacturer string) {
	if mac = strings.ToUpper(mac); !slices.Contains(LAcode, string(strings.ReplaceAll(mac, ":", "")[1])) {
		for _, data := range macdb {
			if strings.HasPrefix(mac, data.Mac) {
				return data.Manufacturer
			}
		}
	} else {
		return "<Invalid OUI>"
	}
	return "<?>"
}

// Get interface info (mode, channel, RSSI, driver, chipset)
func GetIfaceInfo(nameiface string) (interfaceInfo []string, err bool) {
	if busInfo, err := Rtexec(exec.Command("bash", "-c", fmt.Sprintf("cut -d \":\" -f 2 \"/sys/class/net/%s/device/modalias\" | cut -b 1-10 | sed 's/^.//;s/p/:/'", nameiface))); !err {
		if chipset, err1 := Rtexec(exec.Command("bash", "-c", fmt.Sprintf("lsusb -d \"%s\" | head -n1 - | cut -f3- -d \":\" | sed 's/^....//;s/ Network Connection//g;s/ Wireless Adapter//g;s/^ //'", busInfo))); !err1 {
			if strings.Contains(chipset, "Usage: lsusb") {
				chipset = ""
			}
			if mode_ch_dbm, err2 := Rtexec(exec.Command("bash", "-c", fmt.Sprintf("iw %s info | grep -E \"type|channel|txpower\" | awk '{print $2}'", nameiface))); !err2 {
				var mode_ch_dbm_list []string = strings.Split(mode_ch_dbm, "\n")
				if driver, err3 := mon.GetDriver(nameiface); !err3 && len(mode_ch_dbm_list) > 2 {
					return []string{mode_ch_dbm_list[0], mode_ch_dbm_list[1], mode_ch_dbm_list[2], driver, strings.ReplaceAll(chipset, "\n", "")}, false
				}
			}
		}
	}
	return nil, true
}

// Get pcap handler from interface
func GetMonitorSniffer(nameiface string, color Colors) (handle *pcap.Handle) {
	var getSniffer func() (*pcap.Handle, bool) = func() (*pcap.Handle, bool) {
		inactive, err := pcap.NewInactiveHandle(nameiface)
		defer inactive.CleanUp()
		if err != nil {
			return nil, true
		}
		inactive.SetRFMon(true)
		inactive.SetSnapLen(65536)
		inactive.SetPromisc(true)
		inactive.SetTimeout(pcap.BlockForever)
		if handler, err := inactive.Activate(); err == nil {
			return handler, false
		} else {
			return nil, true
		}
	}
	for i := 0; i < maxRetryMonitorSniffer; i++ {
		if handler, retry := getSniffer(); !retry {
			return handler
		}
	}
	fmt.Println()
	Error(color, "Unable to create monitor sniffer handler.\n")
	go Loading(fmt.Sprintf("[%sEXIT%s] Setting up managed mode", color.Blue, color.White), mtLoading)
	SetManagedMode(nameiface)
	time.Sleep(1200 * time.Millisecond)
	mtLoading <- true
	defer os.Exit(1)
	time.Sleep(800 * time.Millisecond)
	return nil
}

// Get source and destination from EAPOLKey layer
func GetEAPOL_APSTA(packet gopacket.Packet) (ap string, sta string) {
	if dot11Layer := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11); dot11Layer != nil {
		if eapol := packet.Layer(layers.LayerTypeEAPOLKey); eapol != nil {
			if key := eapol.(*layers.EAPOLKey); key.KeyType == layers.EAPOLKeyTypePairwise {
				if dot11Layer.Flags.FromDS() {
					sta = dot11Layer.Address1.String()
					ap = dot11Layer.Address2.String()
				} else if dot11Layer.Flags.ToDS() {
					sta = dot11Layer.Address2.String()
					ap = dot11Layer.Address1.String()
				}
			}
		}
	}
	return
}

// Get cipher suite name from ID
func getCipherFromID(cipherID uint8) (cipher string) {
	switch cipherID {
	case 1:
		return "WEP"
	case 2:
		return "TKIP"
	case 3:
		return "WRAP"
	case 4:
		return "CCMP"
	case 5:
		return "WEP104"
	case 6:
		return "CMAC"
	case 8:
		return "GCMP"
	case 9:
		return "GCMP256"
	case 10:
		return "CCMP256"
	case 11:
		return "GMAC"
	case 12:
		return "GMAC256"
	case 13:
		return "CMAC256"
	default:
		return "UNK"
	}
}

// Get auth suite name from ID
func getAKMFromID(authID uint8) (auth string) {
	switch authID {
	case 1:
		return "MGT"
	case 2:
		return "PSK"
	case 3:
		return "FT/MGT256"
	case 4:
		return "FT/PSK"
	case 5:
		return "MGT256"
	case 6:
		return "PSK256"
	case 7:
		return "TDLS"
	case 8, 24:
		return "SAE"
	case 9, 25:
		return "FT/SAE"
	case 10:
		return "APPeerKey"
	case 11:
		return "MGT-B"
	case 12:
		return "MGT-CNSA"
	case 13:
		return "FT/MGT-384"
	case 14:
		return "FILS/MGT"
	case 15:
		return "FILS/MGT-384"
	case 16:
		return "FT/FILS-256"
	case 17:
		return "FT/FILS-384"
	case 19:
		return "FT/PSK-384"
	case 20:
		return "PSK-384"
	default:
		return "UNK"
	}
}

// Check if cipher and AKM they are associated for WPA-3
func isWPA3Suite(auth string) (bool) {
	switch auth {
	case "FT/SAE", "SAE":
		return true
	}
	return false
}

// Get channel from beacon sublayer (DSSet)
func GetAPChannel(packet gopacket.Packet) (channel int) {
	for _, layer := range packet.Layers() {
		if info, exist := layer.(*layers.Dot11InformationElement); exist && info.ID == layers.Dot11InformationElementIDDSSet && len(info.Info) > 0 {
			return int(info.Info[0])
		}
	}
	return -1
}

// Get encryption suite (security protocol, cipher suite, auth suite) Syntax: <enc [cipher, auth]>
func GetENCSuite(packet gopacket.Packet) (encSuite string) {
	var cipher, auth string = "UNK", "UNK"
	encSuite = "OPEN"
	if dot11Layer := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11); dot11Layer != nil {
		if dot11Layer.Flags.WEP() {
			return "WEP "
		} else {
			for _, layer := range packet.Layers() {
				if layer.LayerType() == layers.LayerTypeDot11InformationElement {
					if info, exist := layer.(*layers.Dot11InformationElement); exist {
						var buf []byte = info.Info
						if info.ID == layers.Dot11InformationElementIDRSNInfo {
							encSuite = "WPA2"
							if len(buf) > 7 {
								var rsnCipherCount uint16 = binary.LittleEndian.Uint16(buf[6:8])
								buf = buf[8:] 
								if len(buf) > int(rsnCipherCount)*4 {
									buf = buf[(rsnCipherCount-1)*4:]
									cipher = getCipherFromID(buf[3])
									buf = buf[4:]
								}
								if len(buf) > 1 {
									var rsnAuthCount = binary.LittleEndian.Uint16(buf[0:2])
									buf = buf[2:]
									if len(buf) > int(rsnAuthCount)*4 {
										buf = buf[(rsnAuthCount-1)*4:]
										auth = getAKMFromID(buf[3])
									}
								}
							}
							break
						} else if info.ID == layers.Dot11InformationElementIDVendor && info.Length >= 8 && bytes.Equal(info.OUI, []byte{0, 0x50, 0xf2, 1}) && bytes.HasPrefix(info.Info, []byte{1, 0}) {
							encSuite = "WPA "
							if len(buf) > 7 {
								var vendorChiperCount uint16 = binary.LittleEndian.Uint16(buf[6:8])
								buf = buf[8:]
								if len(buf) > int(vendorChiperCount)*4 {
									buf = buf[(vendorChiperCount-1)*4:]
									cipher = getCipherFromID(buf[3])
									buf = buf[4:]
								}
								if len(buf) > 1 {
									var vendorAuthCount = binary.LittleEndian.Uint16(buf[0:2])
									buf = buf[2:]
									if len(buf) > int(vendorAuthCount)*4 {
										buf = buf[(vendorAuthCount-1)*4:]
										auth = getAKMFromID(buf[vendorAuthCount-1*4:][3])
									}
								}
							}
							break
						}
					}
				}
			}
		}
	}
	if encSuite == "OPEN" {return "OPEN"}
	if isWPA3Suite(auth) {
		encSuite = "WPA3"
	}
	if cipher != "UNK" {
		encSuite += fmt.Sprintf(" [%s", cipher)
		if auth != "UNK" {
			return fmt.Sprintf("%s, %s]", encSuite, auth)
		} else {
			return fmt.Sprintf("%s]", encSuite)
		}
	}
	if auth != "UNK" {
		return fmt.Sprintf("%s [%s]", encSuite, auth)
	}
	return encSuite
}

// Get ESSID from beacon sublayers
func GetESSID(packet gopacket.Packet) (ESSID string) {
	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeDot11InformationElement {
			if dot11info, exist := layer.(*layers.Dot11InformationElement); exist && dot11info.ID == layers.Dot11InformationElementIDSSID {	
				if len(dot11info.Info) == 0 {
					return "<hidden>"
				} else if IsValidESSID(string(dot11info.Info)) {
					return string(dot11info.Info)
				}
			}
		}
	}
	return "<unavailable>"
}

// Get RSSI from packet
func GetDBM(packet gopacket.Packet) (dBm int8, err bool) {
	if PWR, exist := packet.Layer(layers.LayerTypeRadioTap).(*layers.RadioTap); PWR != nil && exist {
		return PWR.DBMAntennaSignal, false
	}
	return 0, true
}

// Get source address from beacon
func GetSRCBeacon(packet gopacket.Packet) (src string, err bool) {
	if dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11); dot11 != nil {
		if SRC := dot11.Address2.String(); IsValidMAC(SRC) {
			return strings.ToUpper(SRC), false
		}
	}
	return "", true
}

// Get AP and STA MAC address (for Data layer type)
func GetAPSTAData(packet gopacket.Packet) (AP string, STA string, err bool) {
	if dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11); dot11 != nil {
		var STA string = strings.ToUpper(dot11.Address1.String())
		var AP string = strings.ToUpper(dot11.Address2.String())
		if IsValidMAC(STA) && IsValidMAC(AP) {
			return AP, STA, false
		}
	}
	return "", "", true
}

// Get first row of gapcast software structure (analysis)
func GetRow1(color Colors, capturedEapol []string, globalChannel int, elapsedTime time.Time, offline bool) string {
	var row1 string = "\n"
	if !offline {
		row1 = fmt.Sprintf("%s[%sChannel%s] %s ", color.White, color.Orange, color.White, GetCapsFormat(strconv.Itoa(globalChannel), 3, " "))
	}
	row1 += fmt.Sprintf("[%sELAPSED TIME%s] %s", color.Orange, color.White, SecondsToHMS(int(time.Since(elapsedTime).Seconds())))
	if len(capturedEapol) >= 1 {
		var macsEapol string = strings.Join(capturedEapol, ", ")
		macsEapol = strings.ToUpper(macsEapol)
		row1 += fmt.Sprintf(" %s| [%sWPA-4HANDSHAKE%s] %s", color.White, color.Purple, color.White, macsEapol)
	}
	if !offline {
		return fmt.Sprintf("%s\n\n", row1)
	} else {
		return fmt.Sprintf("%s[%sPCAP%s] Loaded resources:\n%s\n\n", color.White, color.Green, color.White, row1)
	}
}

// Get second row of gapcast software structure (analysis)
func GetRow2(color Colors, paused bool, openTable bool, scene int, tableinj INJTable, src string, dst string, essid string, seqdata []InjectData, err int, ch string) string {
	var row2 string
	if openTable {
		row2 += color.White + "Press [" + color.Yellow + "CTRL-T" + color.White + "] to CLOSE " + color.Red + "INJ Table" + color.White + "\n"
	} else {
		row2 += color.White + "Press [" + color.Yellow + "CTRL-T" + color.White + "] to OPEN " + color.Red + "INJ Table" + color.White + "\n"
	}
	if openTable {
		row2 += GetINJTABLERow(color, scene, tableinj, src, dst, essid, seqdata, err, ch)
	}
	if paused {
		row2 += color.White + "Press [" + color.Yellow + "CTRL-E" + color.White + "] to " + color.Red + "PAUSE " + color.White + "or" + color.Red + " FIX NON-SCAN " + color.White + "[" + color.Blue + "PAUSED" + color.White + "]"
	} else {
		row2 += color.White + "Press [" + color.Yellow + "CTRL-E" + color.White + "] to " + color.Red + "PAUSE " + color.White + "or" + color.Red + " FIX NON-SCAN"
	}
	return row2 + "\n" + color.White + "Press [" + color.Yellow + "CTRL-C" + color.White + "]" + " to " + color.Red + "EXIT" + color.White + "\n"
}

// Add length with "_" to get 12 chars (for writing MAC addresses)
func fcomp(in string) string {
	r := in + strings.Repeat("_", 12)[len(in):]
	var sg []string
	for i := 0; i < len(r); i += 2 {
		if i+2 <= len(r) {
			sg = append(sg, r[i:i+2])
		}
	}
	return strings.Join(sg, ":")
}

// fmac function for lists
func fmaclist(inp []string) string {
	if len(inp) < 1 {
		return "?"
	}
	var macs []string
	for _, in := range inp {
		var r string = strings.ReplaceAll(in, ":", "")
		var sg []string
		for i := 0; i < len(r); i += 2 {
			if i+2 <= len(r) {
				sg = append(sg, r[i:i+2])
			}
		}
		macs = append(macs, strings.ToUpper(strings.Join(sg, ":")))
	}
	return strings.Join(macs, ", ")
}

// Add length with "_" to get 32 chars (for writing ESSIDs)
func fessid(essid string) string {
	return strings.ReplaceAll(essid+strings.Repeat("_", 32-len(essid)), " ", "_")
}

// Add length with "_" to get 3 chars (for writing channels)
func fch(ch string) string {
	return ch + strings.Repeat("_", 3-len(ch))
}

// Get formatted MAC (AA:AA:AA:AA:AA:AA) from raw MAC (aaaaaaaaaaaa)
func Fmac(in string) string {
	var r string = strings.ReplaceAll(in, ":", "")
	var sg []string
	for i := 0; i < len(r); i += 2 {
		if i+2 <= len(r) {
			sg = append(sg, r[i:i+2])
		}
	}
	return strings.ToUpper(strings.Join(sg, ":"))
}

// Get randomized MAC with fake valid OUI
func RandMac() (randomMac string) {
	var mac []string
	mac = append(mac, fmt.Sprintf("%x%s", rand.Intn(16), LAcode[rand.Intn(8)])) // Locally administered code get a valid OUI
	for i := 0; i < 5; i++ {
		mac = append(mac, fmt.Sprintf("%02x", rand.Intn(255)))
	}
	return strings.Join(mac, "")
}

// Get injection row of gapcast software structure
func fseqdata(color Colors, seqdata []InjectData, injdata INJTable) string {
	var toadd, seqw, injtype string
	var failed, successful int = 0, 0
	switch injdata.INJ {
	case "De-Auth":
		injtype = fmt.Sprintf("%sDe-Auth %s(%sReason 7%s)", color.Red, color.White, color.Purple, color.White)
	case "Beacon":
		injtype = fmt.Sprintf("%sBeacon %s(\"%s%s%s\")", color.Red, color.White, color.Purple, injdata.ESSID, color.White)
	}
	for _, s := range seqdata {
		var stats, frseq string = "", ""
		if s.Failed {
			failed++
		} else {
			successful++
		}
		stats += fmt.Sprintf("n.%sSuccess%s: %s%d ", color.Green, color.White, color.White, successful)
		stats += fmt.Sprintf("n.%sFailed%s: %s%d", color.Red, color.White, color.White, failed)
		if s.Seq != "no-value" {
			frseq = fmt.Sprintf("%s%s%s", color.Orange, s.Seq, color.White)
		}
		seqw = fmt.Sprintf("[%s:%s%s%s:%s%d%s] | %s", frseq, color.Yellow, GetCapsFormat(strconv.Itoa(s.Of1), len(strconv.Itoa(s.Of2)), "0"), color.White, color.Yellow, s.Of2, color.White, stats)
		toadd = fmt.Sprintf("%s     |    | Injecting [%s%s%s] with %s : %s\n", color.White, color.Green, Fmac(s.Target), color.White, injtype, seqw)
	}
	return toadd
}

// Get INJ Table row of gapcast software structure
func GetINJTABLERow(color Colors, graph int, tableinj INJTable, src string, dst string, essid string, seqdata []InjectData, injerr int, injch string) (row string) {
	var rowinj string

	rowinj += ">  ==================================" + color.Null + color.White + "\n"
	rowinj += color.White + "                                    \n" + color.White
	switch graph {
	case 0:
		rowinj += color.White + "     | [" + color.Blue + "INJ" + color.White + "] ?\n" + color.White
	default:
		rowinj += color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
	}
	rowinj += color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
	switch graph {
	case 10, 11:
		rowinj += color.White + "     | [" + color.Blue + "DST" + color.White + "] FF:FF:FF:FF:FF:FF\n" + color.White
	default:
		rowinj += color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
	}

	switch graph {
	case 0:
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select [" + color.Blue + "INJ" + color.White + "] :\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "De-Auth" + color.White + "\n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Beacon" + color.White + "\n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "3" + color.White + "] for " + color.Red + "Evil-Twin" + color.White + "\n" + color.White
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 1:
		if tableinj.INJ == "Beacon" {
			rowinj += color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + ValidPositiveNumberTest(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
			rowinj += color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + StringEmptyTest(tableinj.ESSID) + "\n" + color.White
		}
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select [" + color.Blue + "SRC" + color.White + "] :\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "Custom" + color.White + " [...]\n" + color.White
		if tableinj.INJ == "De-Auth" {
			rowinj += color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "All BSSID" + color.White + "\n" + color.White
		} else if tableinj.INJ == "Beacon" {
			rowinj += color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Random" + color.White + "\n" + color.White
		}
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 2:
		if tableinj.INJ == "Beacon" {
			rowinj += color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + ValidPositiveNumberTest(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
			rowinj += color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + StringEmptyTest(tableinj.ESSID) + "\n" + color.White
		}
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select [" + color.Blue + "SRC" + color.White + "] :\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		if tableinj.INJ == "EvilTwin" {
			rowinj += color.White + "     |     Type target mac address:  \n" + color.White
		} else {
			rowinj += color.White + "     |     Type custom mac address:  \n" + color.White
		}
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     " + fcomp(src) + "         \n" + color.White
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 3:
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select [" + color.Blue + "DST" + color.White + "] :\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "Random" + color.White + "\n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Broadcast" + color.White + "\n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "3" + color.White + "] for " + color.Red + "Custom" + color.White + " [...]\n" + color.White
		if tableinj.INJ == "De-Auth" && len(tableinj.SRC) == 1 {
			rowinj += color.White + "     |     Press [" + color.Yellow + "4" + color.White + "] for " + color.Red + "All Stations" + color.White + "\n" + color.White
		}
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 4:
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select [" + color.Blue + "DST" + color.White + "] :\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Type custom mac address:  \n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     " + fcomp(dst) + "         \n" + color.White
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 5:
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select another [" + color.Blue + "SRC" + color.White + "] ?\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "Select" + color.White + " [...]\n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Continue" + color.White + "\n" + color.White
		rowinj += color.White + "                                     \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 6:
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select another [" + color.Blue + "DST" + color.White + "] ?\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "Select" + color.White + " [...]\n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Continue" + color.White + "\n" + color.White
		rowinj += color.White + "                                     \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 7:
		if tableinj.INJ == "Beacon" {
			rowinj += color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + ValidPositiveNumberTest(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
			rowinj += color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + StringEmptyTest(tableinj.ESSID) + "\n" + color.White
		}
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Ready for injection.\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Press [" + color.Yellow + "CTRL-D" + color.White + "] to START " + color.Red + "Injection" + color.White + "\n" + color.White
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 8:
		rowinj += ">  ==================================" + color.Null + color.White + "\n"
		rowinj += color.White + "                                    \n" + color.White
		rowinj += color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
		rowinj += color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
		rowinj += color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
		if tableinj.INJ == "Beacon" {
			rowinj += color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + ValidPositiveNumberTest(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
			rowinj += color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + StringEmptyTest(tableinj.ESSID) + "\n" + color.White
		}
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Injection in progress.\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |    | Press [" + color.Yellow + "CTRL-D" + color.White + "] to STOP " + color.Red + "Injection" + color.White + "\n" + color.White
		rowinj += fseqdata(color, seqdata, tableinj)
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 9:
		if injerr == 1 {
			switch tableinj.INJ {
			case "De-Auth":
				rowinj += color.White + "     |                            	 \n" + color.White
				rowinj += color.White + "     | [" + color.Red + "ERROR" + color.White + "] You cannot specify an [" + color.Blue + "SRC" + color.White + "] on De-Auth mode that has not been scanned.\n" + color.White
				rowinj += color.White + "                                     \n" + color.White
				rowinj += "   ==================================" + color.Null + color.White + "\n\n"
			case "Beacon":
				rowinj += color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + ValidPositiveNumberTest(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
				rowinj += color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + StringEmptyTest(tableinj.ESSID) + "\n" + color.White
				rowinj += color.White + "     |                            	 \n" + color.White
				rowinj += color.White + "     | [" + color.Red + "ERROR" + color.White + "] The [" + color.Blue + "ESD" + color.White + "] is invalid, insert a valid ESSID.\n" + color.White
				// ESSID rule https://www.cisco.com/assets/sol/sb/WAP321_Emulators/WAP321_Emulator_v1.0.0.3/help/Wireless05.html
				rowinj += color.White + "                                     \n" + color.White
				rowinj += "   ==================================" + color.Null + color.White + "\n\n"
			case "EvilTwin":
				rowinj += color.White + "     |                            	 \n" + color.White
				rowinj += color.White + "     | [" + color.Red + "ERROR" + color.White + "] You cannot specify an [" + color.Blue + "SRC" + color.White + "] on Evil-Twin mode that has not been scanned.\n" + color.White
				rowinj += color.White + "                                     \n" + color.White
				rowinj += "   ==================================" + color.Null + color.White + "\n\n"
			}
		} else if injerr == 2 {
			if tableinj.INJ == "Beacon" {
				rowinj += color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + ValidPositiveNumberTest(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
				rowinj += color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + StringEmptyTest(tableinj.ESSID) + "\n" + color.White
				rowinj += color.White + "     |                            	 \n" + color.White
				rowinj += color.White + "     | [" + color.Red + "ERROR" + color.White + "] The [" + color.Blue + "CHN" + color.White + "] is invalid, insert a valid channel.\n" + color.White
				rowinj += color.White + "                                     \n" + color.White
				rowinj += "   ==================================" + color.Null + color.White + "\n\n"
			} else if tableinj.INJ == "De-Auth" {
				rowinj += color.White + "     |                            	 \n" + color.White
				rowinj += color.White + "     | [" + color.Red + "ERROR" + color.White + "] The [" + color.Blue + "SRC" + color.White + "] stations were not found.\n" + color.White
				rowinj += color.White + "                                     \n" + color.White
				rowinj += "   ==================================" + color.Null + color.White + "\n\n"
			}
		}
	case 10:
		rowinj += color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + ValidPositiveNumberTest(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
		rowinj += color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + StringEmptyTest(tableinj.ESSID) + "\n" + color.White
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select [" + color.Blue + "ESD" + color.White + "] :\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Type custom ESSID:  \n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     " + fessid(essid) + "         \n" + color.White
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	case 11:
		rowinj += color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + ValidPositiveNumberTest(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
		rowinj += color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + StringEmptyTest(tableinj.ESSID) + "\n" + color.White
		rowinj += color.White + "     |                            	 \n" + color.White
		rowinj += color.White + "     | Select [" + color.Blue + "CHN" + color.White + "] :\n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     Type custom channel:  \n" + color.White
		rowinj += color.White + "     |                               \n" + color.White
		rowinj += color.White + "     |     " + fch(injch) + "         \n" + color.White
		rowinj += color.White + "                                    \n" + color.White
		rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	}
	return rowinj
}

// Get a list with individuals elements
func GetNoDuplicates(l []string) []string {
	if len(l) < 1 {
		return l
	}
	sort.Strings(l)
	var prev int = 1
	for curr := 1; curr < len(l); curr++ {
		if l[curr-1] != l[curr] {
			l[prev] = l[curr]
			prev++
		}
	}
	return l[:prev]
}

// Add custom length with with custom character
func GetCapsFormat(n string, length int, ch string) string {
	return strings.Repeat(ch, length-len(n)) + n
}
