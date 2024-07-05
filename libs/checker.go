package libs

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	chars string  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-& "
)

func IsBeacon(packet gopacket.Packet) (bool) {
	return packet.Layer(layers.LayerTypeDot11).(*layers.Dot11).Type == layers.Dot11TypeMgmtBeacon
}

func IsValidESSID(essid string) (bool) {
	// ESSID rule https://www.cisco.com/assets/sol/sb/WAP321_Emulators/WAP321_Emulator_v1.0.0.3/help/Wireless05.html
	if len(essid) < 2 || len(essid) > 32 {
		return false
	}
	if essid[0] == '!' || essid[0] == '#' || essid[0] == ';' {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9\x20\x21\x23\x25-\x2A\x2C-\x3E\x40-\x5A\x5E-\x7E]+$`).MatchString(essid)
}

func IsValid(data string) (bool) {
	if len(data) < 1 {
		return false
	}
	for _, char := range data {
		if !strings.ContainsRune(chars, char) {
			return false
		}
	}
	return true
}

func IsValidMAC(mac string) (bool) {
	return regexp.MustCompile("^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$").MatchString(mac)
}

func WriterCheck(file string) (bool) {
	if file != "?" {
		if pcapFile, err := os.Create(file); err == nil {
			defer pcapFile.Close()
			return true
		}
		defer os.Exit(1)
		fmt.Println("File not found.")
		fmt.Println()
		return false
	}
	return false
}

func ReaderCheck(file string) (bool) {
	if file == "?" {
		return false
	} 
	if _, err := os.Stat(file); err != nil {
		defer os.Exit(1)
		fmt.Println("File not found.")
		fmt.Println()
		return false
	}
	return true
}

func MonManagementCheck() (bool) {
	var err bool
	if runtime.GOOS == "windows" {
		_, err = Rtexec(exec.Command("cmd", "/c", "wlanhelper"))
	} else {
		_, err = Rtexec(exec.Command("airmon-ng"))
	}
	return !err
}

func MonSupportCheck(nameiface string) (bool) {
	// only for linux systems
	_, err := Rtexec(exec.Command("bash", "-c", "iw \"$(ls /sys/class/net/" + nameiface + "/device/ieee80211 | awk '{print $1}')\" info | grep monitor"))
	return !err
}

func G5Check(nameiface string) (bool) {
	if runtime.GOOS == "windows" {
		if output, err := Rtexec(exec.Command("cmd", "/c", "netsh", "wlan", "show", "drivers", nameiface)); !err {
			for _, out := range strings.Split(output, "\n") {
				out = strings.ToLower(out)
				if strings.Contains(out, "radio") {
					for _, band := range []string{"802.11a", "802.11n", "802.11ac", "802.11ax"} {
						if strings.Contains(out, band) {
							return true
						}
					}
				}
			}
		}
		return false
	} else {
		if output, err := Rtexec(exec.Command("iwlist", nameiface, "freq")); !err {
			var f []string = strings.Split(strings.ReplaceAll(strings.Split(output, "\n")[0], "channels in total; available frequencies :", ""), " ")
			if schan, err2 := strconv.Atoi(f[len(f)-2]); err2 == nil && schan > 14 {
				return true
			}
		}
		return false
	}
}

func AlreadyMon(nameiface string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	for _, command := range []string{"iwconfig " + nameiface + " | grep Mode | awk '{print $1}' | sed 's/Mode:'",
									 "iw " + nameiface + " info | grep type | awk '{print $2}'"} {
		mode, err := Rtexec(exec.Command("bash", "-c", command))
		if !err && strings.EqualFold(strings.ReplaceAll(mode, "\n", ""), "monitor") {
			return true
		}
	}
	return false
}

func TrElement(element string) string {
	if len(element) > 0 {
		return element
	}
	return "?"
}

func TrElementCh(elementch string) string {
	ecint, _ := strconv.Atoi(elementch) 
	if ecint > 0 {
		return elementch
	}
	return "?"
}

func RootCheck() bool {
	if user, err := user.Current(); err == nil {
		return user.Username == "root"
	}
	return false // unable to see current user
}

func IsRunning(process string) (bool) {
	// only for linux systems
	if anything, _ := Rtexec(exec.Command("pidof", process)); anything == "" {
		return false
	}
	return true
}