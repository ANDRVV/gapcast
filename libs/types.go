package libs

import (
	"time"
)

type InjectData struct {
    Of1    int
    Of2    int
    Target string
    Failed bool
    Seq    string
}

type INJTable struct {
    DST     []string 
    SRC     []string
    INJ     string
    ESSID   string
    CHANNEL int
}

type Colors struct {
    Red       string
    White     string
    Yellow    string
    Blue      string
    Purple    string
    Cyan      string
    Orange    string
    Green     string
    Lightblue string 
    Null      string
}

type Ifaces struct {
	Name string 
	Mac  string
}

type Device struct {
    Essid        string 
    Power        int 
    Beacons      int 
    Data         int 
    Ch           int 
    Enc          string
    Manufacturer string
    LastUpdate   time.Time
}

type DeviceClient struct {
    Bssid        string
    Essid        string
    Data         int
    Power        int
    Manufacturer string
    LastUpdate   time.Time
}

type Alldata struct {
    ClientData map[string]DeviceClient
    DeviceData map[string]Device
}