package jsonreader

import (
	"bytes"
	"encoding/json"
	"os"
)

// Read radar config
func ReadRadarConf() (config RadarConf, err bool) {
	path, err1 := os.Getwd()
	if err1 != nil {
		return RadarConf{}, true
	}
	text, err1 := os.ReadFile(path + "/config/radarconf.json")
	if err1 != nil {
		return RadarConf{}, true
	}
	text = bytes.ReplaceAll(text, []byte{13, 10}, []byte{})
	var conf RadarConf
	if err1 := json.Unmarshal(text, &conf); err1 != nil {
		return RadarConf{}, true
	}
	return conf, false
}