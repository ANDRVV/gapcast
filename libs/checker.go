package libs

import (
	"fmt"
	"os"
	"os/exec"
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

func IsBeacon(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeDot11).(*layers.Dot11).Type == layers.Dot11TypeMgmtBeacon
}

func IsValidESSID(essid string) bool {
	// ESSID rule https://www.cisco.com/assets/sol/sb/WAP321_Emulators/WAP321_Emulator_v1.0.0.3/help/Wireless05.html
	if len(essid) < 2 || len(essid) > 32 {
		return false
	}
	if essid[0] == '!' || essid[0] == '#' || essid[0] == ';' {
		return false
	}
	allowedChars := regexp.MustCompile(`^[a-zA-Z0-9\x20\x21\x23\x25-\x2A\x2C-\x3E\x40-\x5A\x5E-\x7E]+$`)
	if !allowedChars.MatchString(essid) {
		return false
	}
	if essid[0] == ' ' || essid[len(essid)-1] == ' ' {
		return false
	}
	return true
}

func IsValid(data string) bool {
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

func IsValidMAC(mac string) bool {
	return regexp.MustCompile("^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$").MatchString(mac)
}

func WriterCheck(file string) bool {
	if file != "?" {
		pcapFile, err := os.Create(file)	
		if err != nil {
			defer os.Exit(1)
			fmt.Println("File not found.")
			fmt.Println()
			return false
		}
		defer pcapFile.Close()
		return true
	}
	return false
}

func ReaderCheck(file string) bool {
	if file != "?" {
		if _, err := os.Stat(file); err != nil {
			defer os.Exit(1)
			fmt.Println("File not found.")
			return false
		}
		return true
	}
	return false
}

func MonSupportCheck() bool {
	if runtime.GOOS == "windows" {
		if _, err := Rtexec(exec.Command("cmd", "/c", "wlanhelper")); err {
			return false
		}
	} else {
		if _, err := Rtexec(exec.Command("airmon-ng")); err {
			return false
		}
	}
	return true
}

func G5Check(nameiface string) bool {
	if runtime.GOOS == "windows" {
		output, err := Rtexec(exec.Command("cmd", "/c", "netsh", "wlan", "show", "drivers", nameiface))
		if err {
			return false
		}
		for _, out := range strings.Split(output, "\n") {
			if strings.Contains(strings.ToLower(out), "radio") && (strings.Contains(strings.ToLower(out), "802.11a") || strings.Contains(strings.ToLower(out), "802.11n") || strings.Contains(strings.ToLower(out), "802.11ac") || strings.Contains(strings.ToLower(out), "802.11ax")) {
				return true
			}
		}
		return false
	} else {
		output, err := Rtexec(exec.Command("iwlist", nameiface, "freq"))
		if err {
			return false
		}
		var f []string = strings.Split(strings.ReplaceAll(strings.Split(output, "\n")[0], "channels in total; available frequencies :", ""), " ")
		schan, err2 := strconv.Atoi(f[len(f)-2])
		if err2 != nil || schan <= 15 {
			return false
		}
		return true
	}
}

func AlreadyMon(nameiface string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	for _, command := range []string{
		"iwconfig " + nameiface + " | grep Mode | awk '{print $1}' | sed 's/Mode:'",
		"iw " + nameiface + " info | grep type | awk '{print $2}'",
	} {
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