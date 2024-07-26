package libs

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
)

// Check if the main layer is a beacon
func IsBeacon(packet gopacket.Packet) (isBeacon bool) {
	return packet.Layer(layers.LayerTypeDot11).(*layers.Dot11).Type == layers.Dot11TypeMgmtBeacon
}

// Check if the main layer is data
func IsData(packet gopacket.Packet) (isData bool) {
	return packet.Layer(layers.LayerTypeDot11).(*layers.Dot11).Type.MainType() == layers.Dot11TypeData
}

// Check if ESSID is valid according to https://www.cisco.com/assets/sol/sb/WAP321_Emulators/WAP321_Emulator_v1.0.0.3/help/Wireless05.html
func IsValidESSID(essid string) (essidIsValid bool) {
	if len(essid) > 1 && len(essid) < 33 { // ESSID must be long > 1 but < 33
		if !strings.ContainsAny(essid[0:1], "!#;") { // #!; characters is invalid on first index
			return regexp.MustCompile(`^[a-zA-Z0-9\x20\x21\x23\x25-\x2A\x2C-\x3E\x40-\x5A\x5E-\x7E]+$`).MatchString(essid)
		}
	}
	return false
}

// Check if MAC is valid
func IsValidMAC(mac string) (macIsValid bool) {
	return regexp.MustCompile("^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$").MatchString(mac)
}

// Check if pcap file is writable/createable
func WriterCheck(file string) (canMake bool) {
	if file != "?" {
		if pcapFile, err := os.Create(file); err == nil { //
			defer pcapFile.Close()
			return true
		}
		defer os.Exit(1)
		fmt.Print("File not found.\n\n")
	}
	return false
}

// Check if file exist
func ReaderCheck(file string) (fileExist bool) {
	if file != "?" {
		if _, err := os.Stat(file); err == nil {
			return true
		} else {
			defer os.Exit(1)
			fmt.Print("File not found.\n\n")
		}
	}
	return false
}

// Check if software is present
func SoftwareCheck(appName string) (exist bool) {
	out, _ := Rtexec(exec.Command("bash", "-c", appName))
	return !strings.Contains(out, "command not found")
}

// Check if software.service is present
func SoftwareServiceCheck(appName string) (exist bool) {
	_, err := Rtexec(exec.Command("bash", "-c", fmt.Sprintf("dpkg --get-selections | grep %s", appName)))
	return !err
}

// Check if interface support monitor mode
func MonSupportCheck(nameiface string) (ifaceSupportMonitor bool) {
	_, err := Rtexec(exec.Command("bash", "-c", fmt.Sprintf("iw \"$(ls /sys/class/net/%s/device/ieee80211 | awk '{print $1}')\" info | grep monitor", nameiface)))
	return !err
}

// Check if iface support 5 Ghz
func G5Check(nameiface string) (support5G bool) {
	if output, err := Rtexec(exec.Command("bash", "-c", fmt.Sprintf("iwlist %s freq", nameiface))); !err {
		var f []string = strings.Split(strings.ReplaceAll(strings.Split(output, "\n")[0], "channels in total; available frequencies :", ""), " ")
		if schan, err2 := strconv.Atoi(f[len(f)-2]); err2 == nil && schan > 14 { // Check if support channels > 14 (like 36, 48...)
			return true
		}
	}
	return false
}

// Check if iface is currently in monitor mode
func AlreadyMon(nameiface string) (alreadyInMonitor bool) {
	for _, command := range []string{
		fmt.Sprintf("iwconfig %s | grep Mode | awk '{print $1}' | sed 's/Mode:'", nameiface),
		fmt.Sprintf("iw %s info | grep type | awk '{print $2}'", nameiface)} {
		if mode, err := Rtexec(exec.Command("bash", "-c", command)); !err && strings.EqualFold(strings.ReplaceAll(mode, "\n", ""), "monitor") {
			return true
		}
	}
	return false
}

// Check if string isn't empty, else return "?"
func StringEmptyTest(element string) string {
	if len(element) > 0 {
		return element
	}
	return "?"
}

// Check if number is valid/greater than 0, else return "?"
func ValidPositiveNumberTest(number string) string {
	if intn, _ := strconv.Atoi(number); intn > 0 {
		return number
	}
	return "?"
}

// Check if current user is in root/Administrator
func RootCheck() (root bool) {
	if user, err := user.Current(); err == nil {
		return user.Username == "root"
	}
	return false // unable to see current user
}

// Check if process running
func IsRunning(process string) (isRunning bool) {
	if anything, _ := Rtexec(exec.Command("pidof", process)); anything == "" {
		return false
	}
	return true
}
