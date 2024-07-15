package injpacket

import (
	"github.com/andrvv/gapcast/v1.0.3-beta/libs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Convert packet (gopacket model) to byte list
func bytesConv(layers ...gopacket.SerializableLayer) (err bool, rawPacket []byte) {
	var buf gopacket.SerializeBuffer = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, layers...); err != nil {
		return true, nil
	}
	return false, buf.Bytes()
}

// Inject packet to destination
func InjectPacket(handle *pcap.Handle, nameiface string, channel int, prevch int, layers []gopacket.SerializableLayer) (success bool) {
	if err, packet := bytesConv(layers...); !err {
		if prevch != channel {
			libs.ChangeChannel(nameiface, channel)
		}
		return handle.WritePacketData(packet) == nil
	}
	return false
}
