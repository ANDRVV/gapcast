package jsonreader

import (
	"bytes"
	"encoding/json"
	"os"
)

// Read vendors database
func ReadMacdb() ([]Macdb, bool) {
	path, err := os.Getwd()
	if err != nil {
		return []Macdb{
			{Mac: "<err>", Manufacturer: "<err>"},
		}, true
	}
	text, err := os.ReadFile(path + "/database/manufacturers.json")
	if err != nil {
		return []Macdb{
			{Mac: "<err>", Manufacturer: "<err>"},
		}, true
	}
	text = bytes.ReplaceAll(text, []byte{13, 10}, []byte{})
	var data map[string]string
	if err := json.Unmarshal(text, &data); err != nil {
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