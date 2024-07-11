package jsonreader

import (
	"bytes"
	"encoding/json"
	"os"
)

// Read radar config
func ReadRadarConf() (RadarConf, bool) {
	path, err := os.Getwd()
	if err != nil {
		return RadarConf{}, true
	}
	text, err := os.ReadFile(path + "/config/radarconf.json")
	if err != nil {
		return RadarConf{}, true
	}
	text = bytes.ReplaceAll(text, []byte{13, 10}, []byte{})
	var conf RadarConf
	if err := json.Unmarshal(text, &conf); err != nil {
		return RadarConf{}, true
	}
	return conf, false
}