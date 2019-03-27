package statistics

var totalReads int

func initializeAverageReads(totalAmountPages uint64) CalculateStatistic {
	reset()
	return calculate
}

func reset() {
	totalReads = 0
}

func calculate(val uint64) {
	totalReads++
}

func GetValue() int {
	return totalReads
}
