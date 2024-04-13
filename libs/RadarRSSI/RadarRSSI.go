package RadarRSSI

import (
	"RadarRSSI/libs"
	"errors"
)

func GetRFDataFromRadiotap(packetData []byte, RXAntennaDBI float64) (libs.RFData, error) {
	if RadioTapInfo := libs.ParseRT(packetData); RadioTapInfo.Channel > 0 {
		RadioTapInfo.ReceivedDBM = RXAntennaDBI
		return RadioTapInfo, nil
	}
	return libs.RFData{}, errors.New("")
}

func GetCustomRFData(ReceivedDBM float64, Channel int, RXAntennaDBI float64) libs.RFData {
	return libs.RFData{ReceivedDBM: ReceivedDBM, Channel: Channel, RXAntennaDBI: RXAntennaDBI}
}

func GetDefaultTransmitterData() libs.TransmitterData {
	return libs.TransmitterData{TXAntennaDBI: 4, TXPowerDBM: 17.5}
}

func GetCustomTransmitterData(TXAntennaDBI float64, TXPowerDBM float64) libs.TransmitterData {
	return libs.TransmitterData{TXAntennaDBI: TXAntennaDBI, TXPowerDBM: TXPowerDBM}
}

func GetAutoDBPathLoss(RFData libs.RFData) (DBPathLoss float64) {
	if RFData.ReceivedDBM > -8 {
		return 0
	} else {
		if RFData.Channel < 15 {
			return 0.65 * (-RFData.ReceivedDBM) - 12  
		}
		return 0.55 * (-RFData.ReceivedDBM) - 8.22
	} 
}

func Radiolocate(RFData libs.RFData, TXData libs.TransmitterData, DBPathLoss float64) (meters float64) {
	var info []float64 
	info = append(info, RFData.RXAntennaDBI)
	info = append(info, TXData.TXAntennaDBI)
	info = append(info, TXData.TXPowerDBM)
	info = append(info, float64(RFData.Channel))
	info = append(info, RFData.ReceivedDBM - DBPathLoss)
	return libs.CalculateFriis(info)
}