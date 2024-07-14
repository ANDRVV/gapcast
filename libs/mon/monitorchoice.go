package mon

import (
	"fmt"
	chipset "github.com/andrvv/gapcast/libs/mon/chipset"
	"os/exec"
	"strings"
)

type mode int

const (
	MANAGED mode = 0x01
	MONITOR mode = 0x02
)

// Set mode (monitor, managed) to an interface
func SetMode(nameiface string, toMode mode) (err bool) {
	if driver, err := GetDriver(nameiface); !err {
		if chip, exist := chipset.Drivers[strings.ToLower(driver)]; exist { // select chip for appropiate command
			var err2 bool = true // default is error, in case mode isn't recognized
			switch toMode {
			case MONITOR:
				_, err2 = Rtexec(chipset.BuildCommand(chip.MONITOR, nameiface))
			case MANAGED:
				_, err2 = Rtexec(chipset.BuildCommand(chip.MANAGED, nameiface))
			}
			return err2
		}
	}
	// if chip does not exist or driver cannot be taken try airmon-ng
	if output, err3 := Rtexec(exec.Command("airmon-ng", "start", nameiface)); err3 || strings.Contains(strings.ToUpper(output), "fail") {
		return true
	}
	return false
}

// Get the driver name of interface
func GetDriver(nameiface string) (driverName string, err bool) {
	driver, err := Rtexec(exec.Command("bash", "-c", fmt.Sprintf("ethtool -i %s | grep driver | awk '{print $2}'", nameiface)))
	return strings.ReplaceAll(driver, "\n", ""), err
}

// Execute commands on OS shell
func Rtexec(cmd *exec.Cmd) (output string, err bool) {
	cmdoutput, err1 := cmd.CombinedOutput()
	if err1 != nil {
		if strings.Contains(err1.Error(), "exit status") {
			return string(cmdoutput), true
		}
	}
	return string(cmdoutput), false
}
