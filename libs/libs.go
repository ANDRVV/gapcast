package libs

import (
	"errors"
	"fmt"
	"gapcast/libs/RadarRSSI"
	"gapcast/libs/RadarRSSI/libs"
	"gapcast/libs/jsonreader"
	"gapcast/libs/mon"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	color2 "github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mattn/go-isatty"
	"golang.org/x/exp/slices"
)

var (
	G24channels            [14]int   = [14]int{1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12}
	G5channels             [47]int   = [47]int{36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173}	
	G5g24Channels          [61]int   = [61]int{1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173}
	maxRetryMonitorSniffer int       = 10
	LAcode                 []string  = []string{"2", "6", "A", "E", "3", "7", "B", "F"}
)

var (
	mtLoading chan bool = make(chan bool)
)

const (
	VERSION string = "1.0.2"
)

func ScreenClear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

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
	channels := strings.Split(ch, ",")
	var channelList []int
	for _, channelStr := range channels {
		channel, err := strconv.Atoi(channelStr)
		if err == nil {
			if g5 && !slices.Contains(G5channels[:], channel) {
				return nil, "Channel " + strconv.Itoa(channel) + " is invalid for 5 GHz."
			} else if !slices.Contains(G24channels[:], channel) {
				return nil, "Channel " + strconv.Itoa(channel) + " is invalid for 2.4 GHz."
			}
		} else {
			return nil, "Channel " + strconv.Itoa(channel) + " is invalid."
		}
		channelList = append(channelList, channel)
	}
	return channelList, ""
}

func ShowIfaces() []Ifaces {
	devs, _ := net.Interfaces()
	var ifacelist []Ifaces
    for _, iface := range devs {
		if len(iface.HardwareAddr) > 0 {
			ifacelist = append(ifacelist, Ifaces{Name: iface.Name, Mac: iface.HardwareAddr.String()})
		}
    }
	return ifacelist
}

func SetManagedMode(nameiface string) { 
	if runtime.GOOS == "windows" {
		Rtexec(exec.Command("cmd", "/c", fmt.Sprintf("wlanhelper %s mode managed", nameiface)))
	} else {
		if err := mon.SetMode(nameiface, mon.MANAGED); err {
			for _, ifaces := range ShowIfaces() {
				if strings.Contains(ifaces.Name, nameiface) {
					phyface, _ := Rtexec(exec.Command("bash", "-c", "ls /sys/class/net/" + ifaces.Name + "/device/ieee80211 | awk '{print $1}'"))
					Rtexec(exec.Command("bash", "-c", "iw " + ifaces.Name + " del"))
					Rtexec(exec.Command("bash", "-c", "iw phy " + phyface + " interface add " + nameiface + " type managed"))
					return
				}
			}
		}
	}
}

func SetMonitorMode(nameiface string) (err bool) {
    if runtime.GOOS == "windows" {
		_, err := Rtexec(exec.Command("cmd", "/c", "wlanhelper", nameiface, "mode", "monitor"))
		return err
	} else {
		Rtexec(exec.Command("airmon-ng", "check", "kill"))
		if err := mon.SetMode(nameiface, mon.MONITOR); err {
			return true
		}
		for _, ifaces := range ShowIfaces() {
			if fsiface, _ := strings.CutSuffix(ifaces.Name, "mon"); fsiface == nameiface && ifaces.Name != nameiface {
				if _, err = Rtexec(exec.Command("bash", "-c", "ip link set " + ifaces.Name + " name " + nameiface)); !err {
					return false
				}
				
			}
		}
		for _, ifaces := range ShowIfaces() {
			if strings.Contains(ifaces.Name, nameiface) && ifaces.Name != nameiface {
				_, err = Rtexec(exec.Command("bash", "-c", "ip link set " + ifaces.Name + " name " + nameiface))
			}
		}
		return err
	}
}

func Rtexec(cmd *exec.Cmd) (string, bool) {
	output, err := cmd.CombinedOutput()
    if err != nil || strings.Contains(string(output), "fail") {
		return string(output), true
    }
	return string(output), false
}

func Loading(msg string, mt chan bool) {
	var idx int = 0
	var spinner [4]string = [4]string{"|", "/", "-", "\\"}
	for {
		select {
			case <- mt:
				fmt.Print("\r" + msg + " ... Done\n")
				return
			default:
				fmt.Print("\r" + msg + " [" + spinner[idx] + "] ... ")
				idx = (idx + 1) % 4
				time.Sleep(120 * time.Millisecond)
		}
	}
}

func SetupColors() Colors {
	color2.White("")
	var noColor bool = (os.Getenv("NO_COLOR") != "") || os.Getenv("TERM") == "dumb" || (!isatty.IsTerminal(os.Stdout.Fd()))
	var color Colors
    if noColor {
		color = Colors {
			Red: "",
			White: "",
			Yellow: "",
			Blue: "",
			Purple: "",
			Cyan: "",
			Orange: "",
			Green: "",
			Lightblue: "",
			Null: "",
		}
	} else {
		color = Colors {
			Red: "\033[1;31m",
			White: "\033[1;37m",
			Yellow: "\033[38;5;227m",
			Blue: "\033[1;34m",
			Purple: "\033[1;35m",
			Cyan: "\033[1;36m",
			Orange: "\033[1;38;5;208m",
			Green: "\033[1;32m",
			Lightblue: "\033[38;5;117",
			Null: "\033[0m",
    	}
	}
	fmt.Print(color.White)
	return color
}

func PrintLogo(color Colors, msg string) {
	ScreenClear()
	fmt.Println()
    fmt.Println(color.Green + "         :~7JJJJJ~      ")
    fmt.Println(color.Green + "       !G&@@@@@@@Y      ")
    fmt.Println(color.Green + "      ?@@@@B5JY55^      " + color.Blue + "| ")
    fmt.Println(color.Green + "     ^@@@@J             " + color.Blue + "| " + msg)
    fmt.Println(color.Green + "     5@@@B              " + color.Blue + "| ")
    fmt.Println(color.Green + "    .&@@@J              " + color.Blue + "| Gapcast for fun!")
    fmt.Println(color.Green + "    !@@@@~   .....      " + color.Blue + "| Version " + VERSION)
    fmt.Println(color.Green + "    Y@@@&.  .B&&&7      " + color.Blue + "| ")
    fmt.Println(color.Green + "    G@@@B   ~@@@@^      " + color.Blue + "| https://github.com/ANDRVV/gapcast")
    fmt.Println(color.Green + "   .#@@@5   ?@@@#.      " + color.Blue + "| ")
    fmt.Println(color.Green + "   :&@@@Y   P@@@P       " + color.Blue + "| ")
    fmt.Println(color.Green + "   .#@@@#^.:#@@@?       " + color.Blue + "| ")
    fmt.Println(color.Green + "    !&@@@@##@@@@~.      " + color.Blue + "|                    Andrea Vaccaro")
    fmt.Println(color.Green + "     ^5B&&@&&&#G..      " + color.White + "\n")
}

func SignalError(color Colors, msg string) {
	defer os.Exit(1)
	Error(color, msg)
    time.Sleep(800 * time.Millisecond)
}

func ChangeChannel(nameiface string, channel int) {
	if runtime.GOOS == "windows" {
		Rtexec(exec.Command("cmd", "/c", "wlanhelper", nameiface, "channel", strconv.Itoa(channel)))
	} else {
		Rtexec(exec.Command("iwconfig", nameiface, "channel", strconv.Itoa(channel)))
	}
}

func ParseMac(mac string) net.HardwareAddr {
	parsedMac, _ := net.ParseMAC(mac)
	return parsedMac
}

func SecondsToHMS(seconds int) string {
	var hours int = seconds / 3600
	seconds %= 3600
	var minutes int = seconds / 60
	seconds %= 60
	var result string
	if hours > 0 {
		result += strconv.Itoa(hours) + "h"
        if minutes > 0 || seconds > 0 {
            result += " "
        }
	}
	if minutes > 0 {
		result += strconv.Itoa(minutes) + "m"
        if seconds > 0 {
            result += " "
        }
	}
	if seconds > 0 || result == "" {
		result += strconv.Itoa(seconds) + "s"
	}
	return result
}

func RadioLocalize(ReceivedDBM int, Channel int, radarconf jsonreader.RadarConf) string {
	var RxFData libs.RFData
	var TXData libs.TransmitterData
	if reflect.DeepEqual(radarconf, jsonreader.RadarConf{}) {
		RxFData = RadarRSSI.GetCustomRFData(float64(ReceivedDBM), Channel, 5)
		TXData = RadarRSSI.GetCustomTransmitterData(4, 17.5)
	} else {
		RxFData = RadarRSSI.GetCustomRFData(float64(ReceivedDBM), Channel, radarconf.RXAntennaDBI)
		TXData = RadarRSSI.GetCustomTransmitterData(radarconf.TXAntennaDBI, radarconf.TXPowerDBM)
	}
	return "~" + fmt.Sprintf("%.1f", RadarRSSI.Radiolocate(RxFData, TXData, RadarRSSI.GetAutoDBPathLoss(RxFData))) + "m"
}

func GetManufacturer(macdb []jsonreader.Macdb, mac string) string {
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

func GetIfaceFromName(nameiface string) string {
	if runtime.GOOS != "windows" {
		return nameiface
	}
	devs, _ := net.Interfaces()
	for _, iface := range devs {
		if addr, _ := iface.Addrs(); len(iface.HardwareAddr) > 0 && len(addr) > 1 {
			if strings.EqualFold(iface.Name, nameiface) {
				devs, _ := pcap.FindAllDevs()
				for _, iface := range devs {
					if len(iface.Addresses) > 1 {
						if iface.Addresses[1].IP.String() == strings.Split(addr[1].String(), "/")[0] {
							return iface.Name
						}
					}
				}
			}
		}
	}
	return ""
}

func GetIfaceInfo(nameiface string) ([]string, bool) {
	if busInfo, err := Rtexec(exec.Command("bash", "-c", "cut -d \":\" -f 2 \"/sys/class/net/" + nameiface + "/device/modalias\" | cut -b 1-10 | sed 's/^.//;s/p/:/'")); !err {
		if chipset, err1 := Rtexec(exec.Command("bash", "-c", "lsusb -d \"" + busInfo + "\" | head -n1 - | cut -f3- -d \":\" | sed 's/^....//;s/ Network Connection//g;s/ Wireless Adapter//g;s/^ //'")); !err1 {
			if strings.Contains(chipset, "Usage: lsusb") {
				chipset = ""
			}
			if mode_ch_dbm, err2 := Rtexec(exec.Command("bash", "-c", "iw " + nameiface + " info | grep -E \"type|channel|txpower\" | awk '{print $2}'")); !err2 {
				var mode_ch_dbm_list []string = strings.Split(mode_ch_dbm, "\n")
				if driver, err3 := mon.GetDriver(nameiface); !err3 && len(mode_ch_dbm_list) > 2 {
					return []string{mode_ch_dbm_list[0], mode_ch_dbm_list[1], mode_ch_dbm_list[2], driver, strings.ReplaceAll(chipset, "\n", "")}, false
				}
			}
		}
	}
	return nil, true
}

func GetMonitorSniffer(nameiface string, iface string, color Colors) *pcap.Handle {
	var getSniffer func(string) (*pcap.Handle, bool) = func(iface string) (*pcap.Handle, bool) {
		inactive, err := pcap.NewInactiveHandle(iface)
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
		if handler, retry := getSniffer(iface); !retry {
			return handler
		}
	}
	fmt.Println()
	Error(color, "Unable to create monitor sniffer handler.")
	fmt.Println()
	go Loading("[" + color.Blue + "EXIT" + color.White + "] Setting up managed mode", mtLoading)
	SetManagedMode(nameiface)
	time.Sleep(1200 * time.Millisecond)
	mtLoading <- true
	defer os.Exit(1)
	time.Sleep(800 * time.Millisecond)
	return nil
}

func GetDBM(packet gopacket.Packet) (int8, bool) {
	if PWR, ok := packet.Layer(layers.LayerTypeRadioTap).(*layers.RadioTap); PWR != nil && ok {
		return PWR.DBMAntennaSignal, false
	}
	return 0, true
}

func GetSRCBeacon(packet gopacket.Packet) (string, error) {
	if dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11); dot11 != nil {
		if SRC := dot11.Address2.String(); IsValidMAC(SRC) {
			return strings.ToUpper(SRC), nil
		}
	}
	return "", errors.New("")
}

func GetAPSTDATA(packet gopacket.Packet) (string, string, error) {
	if dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11); dot11 != nil {
		var ST string = dot11.Address1.String()
		var AP string = dot11.Address2.String()
		if IsValidMAC(ST) && IsValidMAC(AP) {
			return strings.ToUpper(AP), strings.ToUpper(ST), nil
		}
	}
	return "", "", errors.New("")
}

func GetRow1(color Colors, capturedEapol []string, globalChannel int, elapsedTime time.Time, offline bool) string {
	var row1 string
	if !offline {
		row1 = "\n" + color.White + "[" + color.Orange + "Channel" + color.White + "] " + GetCapsFormat(strconv.Itoa(globalChannel), 3, " ") + color.White + " [" + color.Orange + "ELAPSED TIME" + color.White + "] " + SecondsToHMS(int(time.Since(elapsedTime).Seconds()))
	} else {
		row1 = "\n" + color.White + "[" + color.Orange + "ELAPSED TIME" + color.White + "] " + SecondsToHMS(int(time.Since(elapsedTime).Seconds()))
	}
	if len(capturedEapol) >= 1 {
		var macsEapol string
		for _, eapolMac := range capturedEapol {
			macsEapol += eapolMac + ", "
		}
		macsEapol, _ = strings.CutSuffix(strings.ToUpper(macsEapol), ", ")
		row1 += color.White + " | [" + color.Purple + "WPA-4HANDSHAKE" + color.White + "] " + macsEapol
	}
	if !offline {
		return row1 + "\n\n"
	} else {
		return color.White + "[" + color.Green + "PCAP" + color.White + "] Loaded resources:" + "\n\n" + row1 + "\n\n"
	}
}

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

func fcomp(in string) string {
	r := in + strings.Repeat("_",12)[len(in):]
	var sg []string
	for i := 0; i < len(r); i += 2 {
		if i + 2 <= len(r) {
			sg = append(sg, r[i:i+2])
		}
	}
	return strings.Join(sg, ":")
}

func fmaclist(inp []string) string {
	if len(inp) < 1 {
		return "?"
	}
	var macs []string
	for _, in := range inp {
		in = strings.ReplaceAll(in, ":", "")
		var r string = in + strings.Repeat(" ", 12)[len(in):]
		var sg []string
		for i := 0; i < len(r); i += 2 {
			if i + 2 <= len(r) {
				sg = append(sg, r[i:i + 2])
			}
		}
		macs = append(macs, strings.ToUpper(strings.Join(sg, ":"))) 
	}
	return strings.Join(macs, ", ")
}

func fessid(essid string) string {
	return strings.ReplaceAll(essid + strings.Repeat("_", 32 - len(essid)), " ", "_")
}

func fch(ch string) string {
	return ch + strings.Repeat("_", 3 - len(ch))
}

func Fmac(in string) string {
	in = strings.ReplaceAll(in, ":", "")
	var r string = in + strings.Repeat(" ", 12)[len(in):]
	var sg []string
	for i := 0; i < len(r); i += 2 {
		if i + 2 <= len(r) {
			sg = append(sg, r[i:i+2])
		}
	} 
	return strings.ToUpper(strings.Join(sg, ":"))
}

func RandMac() string {
	var mac []string
	mac = append(mac, fmt.Sprintf("%x%s", rand.Intn(16), LAcode[rand.Intn(8)])) // Fake valid OUI
	for i := 0; i < 5; i++ {
		mac = append(mac, fmt.Sprintf("%02x", rand.Intn(255)))
	}
	return strings.Join(mac, "") 
}

func fseqdata(color Colors, seqdata []InjectData, injdata INJTable) string {
	var toadd, seqw, injtype string
	var failed, successful int = 0, 0
	switch injdata.INJ {
		case "De-Auth":
			injtype = color.Red + "De-Auth" + color.White + " (" + color.Purple + "Reason 7" + color.White + ")"
		case "Beacon":
			injtype = color.Red + "Beacon" + color.White + " (\"" + color.Purple + injdata.ESSID + color.White + "\")"
	}
	for _, s := range seqdata {
		var stats, frseq string = "", ""
		if s.Failed {
			failed++
		} else {
			successful++
		}
		stats += "n." + color.Green + "Success" + color.White + ": " + color.White + strconv.Itoa(successful)
		stats += " n." + color.Red + "Failed" + color.White + ": " + color.White + strconv.Itoa(failed)
		if s.Seq != "no-value" {
			frseq = color.Orange + s.Seq + color.White + ":"
		}
		seqw = "[" + frseq + color.Yellow + strings.Repeat("0", len(strconv.Itoa(s.Of2)) - len(strconv.Itoa(s.Of1))) + strconv.Itoa(s.Of1) + color.White + ":" + color.Yellow + strconv.Itoa(s.Of2) + color.White + "] | " + stats 
		toadd = color.White + "     |    | Injecting" + " [" + color.Green + Fmac(s.Target) + color.White + "] with " + injtype + " : " + seqw + "\n" + color.White
	}
	return toadd
}

func GetINJTABLERow(color Colors, graph int, tableinj INJTable, src string, dst string, essid string, seqdata []InjectData, injerr int, injch string) string {
	var rowinj string
	switch graph {
		case 0:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] ?\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select [" + color.Blue + "INJ" + color.White + "] :\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "De-Auth" + color.White + "\n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Beacon" + color.White + "\n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "3" + color.White + "] for " + color.Red + "Evil-Twin" + color.White + "\n" + color.White
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 1:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			if tableinj.INJ == "Beacon" {
				rowinj +=            color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + TrElementCh(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
				rowinj +=            color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + TrElement(tableinj.ESSID) + "\n" + color.White
			}
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select [" + color.Blue + "SRC" + color.White + "] :\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "Custom" + color.White + " [...]\n" + color.White
			if tableinj.INJ == "De-Auth" {
				rowinj +=            color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "All BSSID" + color.White + "\n" + color.White
			} else if tableinj.INJ == "Beacon" {
				rowinj +=            color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Random" + color.White + "\n" + color.White
			}
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 2:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			if tableinj.INJ == "Beacon" {
				rowinj +=            color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + TrElementCh(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
				rowinj +=            color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + TrElement(tableinj.ESSID) + "\n" + color.White
			}
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select [" + color.Blue + "SRC" + color.White + "] :\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			if tableinj.INJ == "EvilTwin" {
				rowinj +=            color.White + "     |     Type target mac address:  \n" + color.White
			} else {
				rowinj +=            color.White + "     |     Type custom mac address:  \n" + color.White
			}
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     " + fcomp(src) + "         \n" + color.White
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 3:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select [" + color.Blue + "DST" + color.White + "] :\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "Random" + color.White + "\n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Broadcast" + color.White + "\n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "3" + color.White + "] for " + color.Red + "Custom" + color.White + " [...]\n" + color.White
			if tableinj.INJ == "De-Auth" && len(tableinj.SRC) == 1 {
				rowinj +=            color.White + "     |     Press [" + color.Yellow + "4" + color.White + "] for " + color.Red + "All Stations" + color.White + "\n" + color.White
			}
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 4:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select [" + color.Blue + "DST" + color.White + "] :\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Type custom mac address:  \n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     " + fcomp(dst) + "         \n" + color.White
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 5:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select another [" + color.Blue + "SRC" + color.White + "] ?\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "Select" + color.White + " [...]\n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Continue" + color.White + "\n" + color.White
			rowinj +=            color.White + "                                     \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 6:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select another [" + color.Blue + "DST" + color.White + "] ?\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "1" + color.White + "] for " + color.Red + "Select" + color.White + " [...]\n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "2" + color.White + "] for " + color.Red + "Continue" + color.White + "\n" + color.White
			rowinj +=            color.White + "                                     \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 7:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			if tableinj.INJ == "Beacon" {
				rowinj +=            color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + TrElementCh(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
				rowinj +=            color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + TrElement(tableinj.ESSID) + "\n" + color.White
			}
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Ready for injection.\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Press [" + color.Yellow + "CTRL-D" + color.White + "] to START " + color.Red + "Injection" + color.White + "\n" + color.White
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 8:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
			if tableinj.INJ == "Beacon" {
				rowinj +=            color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + TrElementCh(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
				rowinj +=            color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + TrElement(tableinj.ESSID) + "\n" + color.White
			}
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Injection in progress.\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |    | Press [" + color.Yellow + "CTRL-D" + color.White + "] to STOP " + color.Red + "Injection" + color.White + "\n" + color.White
			rowinj += fseqdata(color, seqdata, tableinj)
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 9:
			if injerr == 1 {
				switch tableinj.INJ {
					case "De-Auth":
						rowinj += ">  ==================================" + color.Null + color.White + "\n"
						rowinj +=            color.White + "                                    \n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
						rowinj +=            color.White + "     |                            	 \n" + color.White
						rowinj +=            color.White + "     | [" + color.Red + "ERROR" + color.White + "] You cannot specify an [" + color.Blue + "SRC" + color.White + "] on De-Auth mode that has not been scanned.\n" + color.White
						rowinj +=            color.White + "                                     \n" + color.White
						rowinj += "   ==================================" + color.Null + color.White + "\n\n"
					case "Beacon":
						rowinj += ">  ==================================" + color.Null + color.White + "\n"
						rowinj +=            color.White + "                                    \n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + TrElementCh(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + TrElement(tableinj.ESSID) + "\n" + color.White
						rowinj +=            color.White + "     |                            	 \n" + color.White
						rowinj +=            color.White + "     | [" + color.Red + "ERROR" + color.White + "] The [" + color.Blue + "ESD" + color.White + "] is invalid, insert a valid ESSID.\n" + color.White
						// ESSID rule https://www.cisco.com/assets/sol/sb/WAP321_Emulators/WAP321_Emulator_v1.0.0.3/help/Wireless05.html
						rowinj +=            color.White + "                                     \n" + color.White
						rowinj += "   ==================================" + color.Null + color.White + "\n\n"
					case "EvilTwin":
						rowinj += ">  ==================================" + color.Null + color.White + "\n"
						rowinj +=            color.White + "                                    \n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
						rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
						rowinj +=            color.White + "     |                            	 \n" + color.White
						rowinj +=            color.White + "     | [" + color.Red + "ERROR" + color.White + "] You cannot specify an [" + color.Blue + "SRC" + color.White + "] on Evil-Twin mode that has not been scanned.\n" + color.White
						rowinj +=            color.White + "                                     \n" + color.White
						rowinj += "   ==================================" + color.Null + color.White + "\n\n"
				}
			} else if injerr == 2 {
				if tableinj.INJ == "Beacon" {
					rowinj += ">  ==================================" + color.Null + color.White + "\n"
					rowinj +=            color.White + "                                    \n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + TrElementCh(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + TrElement(tableinj.ESSID) + "\n" + color.White
					rowinj +=            color.White + "     |                            	 \n" + color.White
					rowinj +=            color.White + "     | [" + color.Red + "ERROR" + color.White + "] The [" + color.Blue + "CHN" + color.White + "] is invalid, insert a valid channel.\n" + color.White
					rowinj +=            color.White + "                                     \n" + color.White
					rowinj += "   ==================================" + color.Null + color.White + "\n\n"
				} else if tableinj.INJ == "De-Auth" {
					rowinj += ">  ==================================" + color.Null + color.White + "\n"
					rowinj +=            color.White + "                                    \n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
					rowinj +=            color.White + "     |                            	 \n" + color.White
					rowinj +=            color.White + "     | [" + color.Red + "ERROR" + color.White + "] The [" + color.Blue + "SRC" + color.White + "] stations were not found.\n" + color.White
					rowinj +=            color.White + "                                     \n" + color.White
					rowinj += "   ==================================" + color.Null + color.White + "\n\n"
				} 
			}
		case 10:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] FF:FF:FF:FF:FF:FF"  + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + TrElementCh(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + TrElement(tableinj.ESSID) + "\n" + color.White
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select [" + color.Blue + "ESD" + color.White + "] :\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Type custom ESSID:  \n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     " + fessid(essid) + "         \n" + color.White
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
		case 11:
			rowinj += ">  ==================================" + color.Null + color.White + "\n"
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] FF:FF:FF:FF:FF:FF"  + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "CHN" + color.White + "] " + TrElementCh(strconv.Itoa(tableinj.CHANNEL)) + "\n" + color.White
			rowinj +=            color.White + "     | [" + color.Blue + "ESD" + color.White + "] " + TrElement(tableinj.ESSID) + "\n" + color.White
			rowinj +=            color.White + "     |                            	 \n" + color.White
			rowinj +=            color.White + "     | Select [" + color.Blue + "CHN" + color.White + "] :\n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     Type custom channel:  \n" + color.White
			rowinj +=            color.White + "     |                               \n" + color.White
			rowinj +=            color.White + "     |     " + fch(injch) + "         \n" + color.White
			rowinj +=            color.White + "                                    \n" + color.White
			rowinj += "   ==================================" + color.Null + color.White + "\n\n"
	}
	return rowinj
}

func GetEncString(exist bool, ENC string, CIPHER string, AUTH string) (bool, string) {
	if !exist {
		return false, ""
	}
	var CIPAUT []string
	if ENC != "OPEN" {
		if !(CIPHER == "UNK" || CIPHER == "" || !IsValid(CIPHER)) {
			CIPAUT = append(CIPAUT, CIPHER)
		}
		if !(AUTH == "UNK" || AUTH == "" || !IsValid(AUTH)) {
			CIPAUT = append(CIPAUT, AUTH)
		}
		if len(CIPAUT) == 2 {
			ENC += " [" + CIPAUT[0] + ", " + CIPAUT[1] + "]"
		} else if len(CIPAUT) == 1 {
			ENC += " [" + CIPAUT[0] + "]"
		}
	} else {
		return true, "OPEN"
	}
	return true, ENC
}

func GetNoDuplicates(l []string) []string {
	if len(l) < 1 {
        return l
    }
    sort.Strings(l)
    var prev int = 1
    for curr := 1; curr < len(l); curr++ {
        if l[curr - 1] != l[curr] {
            l[prev] = l[curr]
            prev++
        }
    }
    return l[:prev]
}

func GetCapsFormat(n string, length int, ch string) string {
	return strings.Repeat(ch, length - len(n)) + n
}