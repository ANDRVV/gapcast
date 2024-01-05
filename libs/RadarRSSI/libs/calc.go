package libs

import (
	"fmt"
	"math"
	"strconv"
)

var (
	toF64 = func(strmeters string) float64 {
		meters, _ := strconv.ParseFloat(strmeters, 64)
		return meters
	}
)

func CalculateFriis(info []float64) float64 { 							   	
	var numerator float64 = Prod(info[:len(info) - 2]) * math.Pow(299792458, 2)
	var semiDenominator float64 = 4 * math.Pi * GetLinearFrequency(int(info[len(info) - 2]))
	var meters float64 = 0.1
	for {
		if 10 * math.Log10(numerator / math.Pow(semiDenominator * meters, 2)) < info[len(info) - 1] {
			if meters > 0.1 {
				return toF64(fmt.Sprintf("%.1f", meters - 0.1))
			}
			return toF64(fmt.Sprintf("%.1f", meters))
		}
		meters += 0.1
	}
}