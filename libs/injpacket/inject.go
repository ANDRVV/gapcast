package injpacket

import (
	"gapcast/libs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func bytesConv(layers ...gopacket.SerializableLayer) (bool, []byte) {
	var buf gopacket.SerializeBuffer = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}, layers...); err != nil {
		return true, nil
	}
	return false, buf.Bytes()
}

func InjectPacket(handle *pcap.Handle, nameiface string, channel int, prevch int, layers []gopacket.SerializableLayer) (SendedSuccessful bool) {
	if err, packet := bytesConv(layers...); !err {
		if prevch != channel {
			libs.ChangeChannel(nameiface, channel)
		}
		return handle.WritePacketData(packet) == nil
	}
	return false
}