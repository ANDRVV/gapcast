package jsonreader

import (
	"bytes"
	"encoding/json"
	"os"
)

// Read Apache2 config
func ReadApache2Conf() (config Apache2Conf, err bool) {
	path, err1 := os.Getwd()
	if err1 != nil {
		return Apache2Conf{}, true
	}
	text, err1 := os.ReadFile(path + "/config/apache2.json")
	if err1 != nil {
		return Apache2Conf{}, true
	}
	text = bytes.ReplaceAll(text, []byte{13, 10}, []byte{})
	var conf Apache2Conf
	if err1 := json.Unmarshal(text, &conf); err1 != nil {
		return Apache2Conf{}, true
	}
	return conf, false
}
