package chipset

import (
	"os/exec"
	"strings"
)

type Chip struct {
	MONITOR []string
	MANAGED []string
}

var (
	Drivers map[string]Chip = map[string]Chip {
		"rtl88xxau": RTL88XXAU,
		"r8187":     RTL8187,
		"rtl8811cu": RTL881XCU,
		"rtl8821cu": RTL881XCU,
	} 
)

var (
	IPIW_MONITOR []string = []string {
		"ip link set <iface> down", 
		"iw dev <iface> set type monitor", 
		"sudo ip link set <iface> up", 
	}
	IPIW_MANAGED []string = []string {
		"ip link set <iface> down", 
		"iw dev <iface> set type managed", 
		"sudo ip link set <iface> up", 
	}
	AIRMON_MONITOR string = "airmon-ng start <iface>"
	AIRMON_MANAGED string = "airmon-ng stop <iface>"
)

var (
	RTL88XXAU Chip = Chip {
		MONITOR: append(IPIW_MONITOR, "iw <iface> set txpower fixed 3000"),
		MANAGED: IPIW_MANAGED,
	}
	RTL8187 Chip = Chip {
		MONITOR: []string{
			"ifconfig <iface> down",
			"rmmod rtl8187",
			"rfkill block all",
			"rfkill unblock all",
			"modprobe rtl8187",
			"ifconfig <iface> up",
			AIRMON_MONITOR,
		},
		MANAGED: []string{
			AIRMON_MANAGED,
		},
	}
	RTL881XCU Chip = Chip {
		MONITOR: IPIW_MONITOR,
		MANAGED: IPIW_MANAGED,
	}
)

func BuildCommand(commands []string, nameiface string) *exec.Cmd {
	return exec.Command("bash", "-c", strings.ReplaceAll(strings.Join(commands, " | "), "<iface>", nameiface))
}