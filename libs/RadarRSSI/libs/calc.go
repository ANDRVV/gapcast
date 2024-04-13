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
	var numerator float64 = math.Sqrt((Prod(info[:len(info) - 2]) * math.Pow(299792458, 2)) / (math.Pow(10, info[len(info) - 1] / 10)))                   
	var denominator float64 = 4 * math.Pi * (GetLinearFrequency(int(info[len(info) - 2])))
	return toF64(fmt.Sprintf("%.1f", numerator / denominator))		
}