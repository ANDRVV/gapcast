package RadarRSSI

import (
	"errors"
	"gapcast/libs/RadarRSSI/libs"
	"math"
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
	return libs.TransmitterData{TXAntennaDBI: 3, TXPowerDBM: 20.5}
}

func GetCustomTransmitterData(TXAntennaDBI float64, TXPowerDBM float64) libs.TransmitterData {
	return libs.TransmitterData{TXAntennaDBI: TXAntennaDBI, TXPowerDBM: TXPowerDBM}
}

func GetAutoDBPathLoss(RFData libs.RFData) (DBPathLoss float64) {
	if RFData.Channel < 15 {
    	var autoDBPL float64 = 0.65 * math.Abs(RFData.ReceivedDBM) + -12  
		if autoDBPL > 10 {
			return autoDBPL
		}
		return 10
	}
	var autoDBPL float64 = 0.5555555555555556 * math.Abs(RFData.ReceivedDBM) + -8.222222222222221 
	if autoDBPL > 2 {
		return autoDBPL
	}
	return 2 
}

func Radiolocate(RFData libs.RFData, TXData libs.TransmitterData, DBPathLoss float64) (meters float64) {
	var totalPathLoss func() float64 = func() float64 {
		if DBPathLoss > 0 {
			return DBPathLoss
		} else {
			if RFData.Channel < 15 {
				return 10
			} else {
				return 2
			}
		}
	}
	var info []float64 
	info = append(info, RFData.RXAntennaDBI)
	info = append(info, TXData.TXAntennaDBI)
	info = append(info, TXData.TXPowerDBM)
	info = append(info, float64(RFData.Channel))
	if RFData.Channel < 15 {
		info = append(info, RFData.ReceivedDBM + totalPathLoss())
	} else {
		info = append(info, RFData.ReceivedDBM + totalPathLoss())
	}
	return libs.CalculateFriis(info)
}