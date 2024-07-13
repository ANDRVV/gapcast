package jsonreader

import (
	"bytes"
	"encoding/json"
	"os"
)

// Read vendors database
func ReadMacdb() (macdb []Macdb, err bool) {
	path, err1 := os.Getwd()
	if err1 != nil {
		return []Macdb{
			{Mac: "<err>", Manufacturer: "<err>"},
		}, true
	}
	text, err1 := os.ReadFile(path + "/database/manufacturers.json")
	if err1 != nil {
		return []Macdb{
			{Mac: "<err>", Manufacturer: "<err>"},
		}, true
	}
	text = bytes.ReplaceAll(text, []byte{13, 10}, []byte{})
	var data map[string]string
	if err1 := json.Unmarshal(text, &data); err1 != nil {
		return []Macdb{
			{Mac: "<err>", Manufacturer: "<err>"},
		}, true
	}
	var dblist []Macdb = make([]Macdb, 0, len(data))
	for key, value := range data {
		dblist = append(dblist, Macdb{Mac: key, Manufacturer: value})
	}
	return dblist, false
}
