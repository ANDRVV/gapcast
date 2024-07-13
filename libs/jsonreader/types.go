package jsonreader

type Macdb struct {
	Mac          string
	Manufacturer string
}

type RadarConf struct {
	TXPowerDBM   float64 `json:"TXPowerDBM"`
	TXAntennaDBI float64 `json:"TXAntennaDBI"`
	RXAntennaDBI float64 `json:"RXAntennaDBI"`
}

type Apache2Conf struct {
	InfoGrabbed string `json:"Info-Grabbed"`
}
