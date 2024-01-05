package libs

type RFData struct {
	ReceivedDBM  float64 
	Channel      int
	RXAntennaDBI float64
}

type TransmitterData struct {
	TXPowerDBM   float64 
	TXAntennaDBI float64
}