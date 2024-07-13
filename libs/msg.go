package libs

import (
	"fmt"
	"time"
)

// Print custom log msg with time
func CustomLog(color Colors, titleColor string, title string, msg string) {
	fmt.Printf("%s[%s%s%s] [%s%s%s] %s\n", color.White, color.Yellow, time.Now().Format("15:04:05"), color.White, titleColor, title, color.White, msg)
}

// Print custom log msg
func NOTIMECustomLog(color Colors, titleColor string, title string, msg string) {
	fmt.Printf("%s[%s%s%s] %s\n", color.White, titleColor, title, color.White, msg)
}

// Print log msg with time
func Log(color Colors, msg string) {
	CustomLog(color, color.Blue, "LOG", msg)
}

// Print log error
func Error(color Colors, msg string) {
	NOTIMECustomLog(color, color.Red, "ERROR", msg)
}

// Print log earning
func Warning(color Colors, msg string) {
	NOTIMECustomLog(color, color.Yellow, "WARNING", msg)
}
