package libs

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ParseRT(RadioTapData []byte) RFData {
	var packet gopacket.Packet = gopacket.NewPacket(RadioTapData, layers.LayerTypeRadioTap, gopacket.Default)
	if packet.Layer(layers.LayerTypeRadioTap) != nil {
		var radiotapLayer *layers.RadioTap = packet.Layer(layers.LayerTypeRadioTap).(*layers.RadioTap)
		return RFData{ReceivedDBM: float64(radiotapLayer.DBMAntennaSignal), Channel: GetChannel(int(radiotapLayer.ChannelFrequency))}
	}
	return RFData{}
}

