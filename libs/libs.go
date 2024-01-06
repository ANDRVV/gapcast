package libs

import (
	"fmt"
	"gapcast/libs/RadarRSSI"
	"gapcast/libs/RadarRSSI/libs"
	"gapcast/libs/jsonreader"
	"gapcast/libs/mon"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
	colo "github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"golang.org/x/exp/slices"
)

var (
	G24channels            [14]int = [14]int{1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12}
	G5channels             [47]int = [47]int{36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173}	
	G5g24Channels          [61]int = [61]int{1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173}
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
		if g5g24 {
			return G5g24Channels[:], ""
		} else if g5 {
			return G5channels[:], ""
		}
		return G24channels[:], ""
	}
	channels := strings.Split(ch, ",")
	var channelList []int
	for _, channelStr := range channels {
		channel, err := strconv.Atoi(channelStr)
		if err != nil {
			return nil, "Channel " + strconv.Itoa(channel) + " is invalid."
		}
		if !g5g24 {
			if g5 {
				if !slices.Contains(G5channels[:], channel) {
					return nil, "Channel " + strconv.Itoa(channel) + " is invalid for 5 GHz."
				}
			} else {
				if !slices.Contains(G24channels[:], channel) {
					return nil, "Channel " + strconv.Itoa(channel) + " is invalid for 2.4 GHz."
				}
			}
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
		Rtexec(exec.Command("cmd", "/c", "wlanhelper", nameiface, "mode", "managed"))
	} else {
		mon.GetMode(nameiface, mon.MANAGED)
	}
}

func SetMonitorMode(nameiface string) (string, bool) {
    if runtime.GOOS == "windows" {
		return Rtexec(exec.Command("cmd", "/c", "wlanhelper", nameiface, "mode", "monitor"))
	} else {
		Rtexec(exec.Command("airmon-ng", "check", "kill"))
		return "", mon.GetMode(nameiface, mon.MONITOR)
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
	colo.White("")
	var noColor bool = (os.Getenv("NO_COLOR") != "") || os.Getenv("TERM") == "dumb" ||
	(!isatty.IsTerminal(os.Stdout.Fd()))
	var color Colors
    if noColor {
		color = Colors{
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
		color = Colors{
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

func PrintLogo(color Colors) {
	ScreenClear()
	fmt.Println()
    fmt.Println(color.Green + "         :~7JJJJJ~      ")
    fmt.Println(color.Green + "       !G&@@@@@@@Y      ")
    fmt.Println(color.Green + "      ?@@@@B5JY55^      " + color.Blue + "| ")
    fmt.Println(color.Green + "     ^@@@@J             " + color.Blue + "| Initializing...")
    fmt.Println(color.Green + "     5@@@B              " + color.Blue + "| ")
    fmt.Println(color.Green + "    .&@@@J              " + color.Blue + "| Gapcast for fun!")
    fmt.Println(color.Green + "    !@@@@~   .....      " + color.Blue + "| Version 1.0.0")
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
	fmt.Println("[" + color.Red + "ERROR" + color.White + "] " + msg)
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
        if minutes > 0 {
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
		TXData = RadarRSSI.GetCustomTransmitterData(radarconf.TXAntennaDBI, radarconf.TXPowerDBM)
	} else {
		RxFData = RadarRSSI.GetCustomRFData(float64(ReceivedDBM), Channel, radarconf.RXAntennaDBI)
		TXData = RadarRSSI.GetCustomTransmitterData(3, 20.5)
	}
	return "~" + fmt.Sprintf("%.1f", RadarRSSI.Radiolocate(RxFData, TXData, RadarRSSI.GetAutoDBPathLoss(RxFData))) + "m"
}