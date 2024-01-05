package libs

import (
	"errors"
	"fmt"
	"gapcast/libs/jsonreader"
	"gapcast/libs/mon"
	"math/rand"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	maxRetryMonitorSniffer int = 10
)

func GetManufacturer(macdb []jsonreader.Macdb, mac string) string {
	mac = strings.ToUpper(mac)
	for _, data := range macdb {
		if strings.HasPrefix(mac, data.Mac) {
			return data.Manufacturer
		}
	}
	return "<?>"
}

func GetIfaceFromName(nameiface string) string {
	if runtime.GOOS != "windows" {
		return nameiface
	}
	devs, _ := net.Interfaces()
	for _, iface := range devs {
		addr, _ := iface.Addrs()
		if len(iface.HardwareAddr) > 0 && len(addr) > 1 {
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
	busInfo, err := Rtexec(exec.Command("bash", "-c", "cut -d \":\" -f 2 \"/sys/class/net/" + nameiface + "/device/modalias\" | cut -b 1-10 | sed 's/^.//;s/p/:/'"))
	if err {
		return nil, true
	}
	chipset, err1 := Rtexec(exec.Command("bash", "-c", "lsusb -d \"" + busInfo + "\" | head -n1 - | cut -f3- -d \":\" | sed 's/^....//;s/ Network Connection//g;s/ Wireless Adapter//g;s/^ //'"))
	if err1 {
		return nil, true
	}
	mode_ch_dbm, err2 := Rtexec(exec.Command("bash", "-c", "iw " + nameiface + " info | grep -E \"type|channel|txpower\" | awk '{print $2}'"))
	if err2 {
		return nil, true
	}
	var mode_ch_dbm_list []string = strings.Split(mode_ch_dbm, "\n")
	driver, err3 := mon.GetDriver(nameiface)
	if err3 {
		return nil, true
	}
	return []string{mode_ch_dbm_list[0], mode_ch_dbm_list[1], mode_ch_dbm_list[2], driver, chipset}, false
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
		handler, err := inactive.Activate()
		if err != nil {
			return nil, true
		}
		return handler, false
	}
	for i := 0; i < maxRetryMonitorSniffer; i++ {
		if handler, retry := getSniffer(iface); !retry {
			return handler
		}
	}
	SetManagedMode(nameiface)
	fmt.Println()
	SignalError(color, "Setting up managed mode.")
	return nil
}

func GetDBM(packet gopacket.Packet) (int8, bool) {
	PWR, err := packet.Layer(layers.LayerTypeRadioTap).(*layers.RadioTap)
	if PWR == nil || !err {
		return 0, true
	}
	return PWR.DBMAntennaSignal, false
}

func GetSRCBeacon(packet gopacket.Packet) (string, error) {
	dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
	if dot11 == nil {
		return "", errors.New("")
	}
	var SRC string = dot11.Address2.String()
	if IsValidMAC(SRC) {
		return strings.ToUpper(SRC), nil
	}
	return "", errors.New("")
}

func GetAPSTDATA(packet gopacket.Packet) (string, string, error) {
	dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
	if dot11 == nil {
		return "", "", errors.New("")
	}
	var ST string = dot11.Address1.String()
	var AP string = dot11.Address2.String()
	if IsValidMAC(ST) && IsValidMAC(AP) {
		return strings.ToUpper(AP), strings.ToUpper(ST), nil
	}
	return "", "", errors.New("")
}

func GetRow1(color Colors, capturedEapol []string, globalChannel int, elapsedTime time.Time, offline bool) string {
	var row1 string
	if !offline {
		row1 = color.White + "[" + color.Orange + "Channel" + color.White + "] " + GetCapsFormat(strconv.Itoa(globalChannel), 3, " ") + color.White + " [" + color.Orange + "ELAPSED TIME" + color.White + "] " + SecondsToHMS(int(time.Since(elapsedTime).Seconds()))
	} else {
		row1 = color.White + "[" + color.Orange + "ELAPSED TIME" + color.White + "] " + SecondsToHMS(int(time.Since(elapsedTime).Seconds()))
	}
	if len(capturedEapol) >= 1 {
		var macsEapol string
		for _, eapolMac := range capturedEapol {
			macsEapol += eapolMac + ", "
		}
		macsEapol, _ = strings.CutSuffix(macsEapol, ", ")
		macsEapol = strings.ToUpper(macsEapol)
		row1 += color.White + " | [" + color.Purple + "WPA-4HANDSHAKE" + color.White + "] " + macsEapol
	}
	if !offline {
		return "\n" + row1 + "\n\n"
	} else {
		return "\n" + color.White + "[" + color.Green + "PCAP" + color.White + "] Loaded resources:"  + "\n\n" + row1 + "\n\n"
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
	r := in + "____________"[len(in):]
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
	for i := 0; i < 6; i++ {
		mac = append(mac, fmt.Sprintf("%02x", rand.Intn(255)))
	}
	return strings.Join(mac, "") 
}

func fseqdata(color Colors, seqdata []InjectData, injdata INJTable) string {
	var toadd, seqw, injtype string
	var failed, successful int = 0, 0
	if injdata.INJ == "De-Auth" {
		injtype = color.Red + "De-Auth" + color.White + " (" + color.Purple + "Reason 7" + color.White + ")"
	} else if injdata.INJ == "Beacon" {
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
			rowinj +=            color.White + "     |     Type custom mac address:  \n" + color.White
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
				if tableinj.INJ == "De-Auth" {
					rowinj += ">  ==================================" + color.Null + color.White + "\n"
					rowinj +=            color.White + "                                    \n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "INJ" + color.White + "] " + tableinj.INJ + "\n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "SRC" + color.White + "] " + fmaclist(tableinj.SRC) + "\n" + color.White
					rowinj +=            color.White + "     | [" + color.Blue + "DST" + color.White + "] " + fmaclist(tableinj.DST) + "\n" + color.White
					rowinj +=            color.White + "     |                            	 \n" + color.White
					rowinj +=            color.White + "     | [" + color.Red + "ERROR" + color.White + "] You cannot specify an [" + color.Blue + "SRC" + color.White + "] on De-Auth mode that has not been scanned.\n" + color.White
					rowinj +=            color.White + "                                     \n" + color.White
					rowinj += "   ==================================" + color.Null + color.White + "\n\n"
				} else if tableinj.INJ == "Beacon" {
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