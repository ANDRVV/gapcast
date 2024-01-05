package mon

import (
	"os/exec"
	"strings"
	chipset "gapcast/libs/mon/chipset"
)

type mode int

const (
	MANAGED mode = 0x01
	MONITOR mode = 0x02
)

func GetMode(nameiface string, toMode mode) (err bool) {
	if driver, err := GetDriver(nameiface); !err {
		if chip, exist := chipset.Drivers[strings.ToLower(driver)]; exist {
			if toMode == MONITOR {
				_, err2 := Rtexec(chipset.BuildCommand(chip.MONITOR, nameiface))
				return err2
			} else if toMode == MANAGED {
				_, err2 := Rtexec(chipset.BuildCommand(chip.MANAGED, nameiface))
				return err2
			}
		} else if output, err3 := Rtexec(exec.Command("airmon-ng", "start", nameiface)); err3 || strings.Contains(strings.ToUpper(output), "fail") {
			return true
		}
	} else {
		if output, err3 := Rtexec(exec.Command("airmon-ng", "start", nameiface)); err3 || strings.Contains(strings.ToUpper(output), "fail") {
			return true
		}
	}
	return false
}

func GetDriver(nameiface string) (string, bool) {
	driver, err := Rtexec(exec.Command("bash", "-c", "ethtool -i " + nameiface + " | grep driver | awk '{print $2}'"))
	return strings.ReplaceAll(driver, "\n", ""), err
}

func Rtexec(cmd *exec.Cmd) (string, bool) {
	output, err := cmd.CombinedOutput()
    if err != nil {
        if strings.Contains(err.Error(), "exit status") {   
            return string(output), true
        }
    }
	return string(output), false
}