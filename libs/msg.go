package libs

import (
	"fmt"
	"time"
)

func CustomLog(color Colors, titleColor string, title string, msg string) {
	fmt.Printf("%s[%s%s%s] [%s%s%s] %s\n", color.White, color.Yellow, time.Now().Format("15:04:05"), color.White, titleColor, title, color.White, msg)
}

func NOTIMECustomLog(color Colors, titleColor string, title string, msg string) {
	fmt.Printf("%s[%s%s%s] %s\n", color.White, titleColor, title, color.White, msg)
}

func Log(color Colors, msg string) {
	CustomLog(color, color.Blue, "LOG", msg)
}

func Error(color Colors, msg string) {
	NOTIMECustomLog(color, color.Red, "ERROR", msg)
}

func Warning(color Colors, msg string) {
	NOTIMECustomLog(color, color.Yellow, "WARNING", msg)
}