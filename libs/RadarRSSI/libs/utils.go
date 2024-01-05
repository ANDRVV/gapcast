package libs

func GetLinearFrequency(channel int) float64 {
	var freq int
	if channel < 14 {
		freq = ((channel - 1) * 5) + 2412
	} else if channel == 14 {
		freq = 2484
	} else if channel < 174 {
		freq = ((channel - 7) * 5) + 5035
	}
	return float64(freq) * 1e6
}

func GetChannel(frequency int) int {
	var channel int
	if frequency < 2473 {
		channel = ((frequency - 2412) / 5) + 1
	} else if frequency == 2484 {
		channel = 14
	} else if frequency > 5034 && frequency < 5866 {
		channel = ((frequency - 5035) / 5) + 7
	}
	return channel
}

func Prod(nums []float64) float64 {
	var prod float64 = 1
	for _, n := range nums {
		prod *= n
	}
	return prod
}