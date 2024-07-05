package libs

import (
	"fmt"
	"time"
)

func Log(color Colors, msg string) {
	fmt.Println(color.White + "[" + color.Yellow + time.Now().Format("15:04:05") + color.White + "] [" + color.Blue + "LOG" + color.White + "] " + msg)
}

func Error(color Colors, msg string) {
	fmt.Println(color.White + "[" + color.Red + "ERROR" + color.White + "] " + msg)
}

func CustomLog(color Colors, titleColor string, title string, msg string) {
	fmt.Println(color.White + "[" + color.Yellow + time.Now().Format("15:04:05") + color.White + "] [" + titleColor + title + color.White + "] " + msg)
}

func NOTIMECustomLog(color Colors, titleColor string, title string, msg string) {
	fmt.Println(color.White + "[" + titleColor + title + color.White + "] " + msg)
}

func Warning(color Colors, msg string) {
	fmt.Println(color.White + "[" + color.Yellow + "WARNING" + color.White + "] " + msg)
}