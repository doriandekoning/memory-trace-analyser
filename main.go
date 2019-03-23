package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	pb "github.com/doriandekoning/memory-trace-analyser/proto"

	"github.com/gogo/protobuf/proto"
)

const fileHeader = "gem5"

type traceSlice []*pb.MemTrace

func main() {
	inputFile := flag.String("input", "", "Input trace file to analyse")
	flag.BoolVar(&debuggingEnabled, "debug", false, "If set to true additional debugging info will be logged")
	flag.Parse()

	Debugf("Using input file located at: '%s'", *inputFile)

	in, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		log.Fatalln("Error reading file:", err)
	}
	headerLength := len([]byte(fileHeader))
	header := string(in[:4])
	if header != fileHeader {
		panic("Input not recognized")
	}
	traces := traceSlice{}
	curOffset := headerLength
	for true {
		nextMessagesize, n := proto.DecodeVarint(in[curOffset:])
		curOffset += n
		if curOffset+int(nextMessagesize) >= len(in) {
			break
		}
		trace := &pb.MemTrace{}
		if err := proto.Unmarshal(in[curOffset:(curOffset+int(nextMessagesize))], trace); err != nil {
			panic(err)
		}
		curOffset += int(nextMessagesize)
		traces = append(traces, trace)
	}
	//TODO can the address range be stored in the header of the trace (along with type of memory)?
	largestMemAddress := traces.findLargestMemAdress()
	traces.calcAverageWriteCountPerPage(largestMemAddress)
	fmt.Println(traces[0:50])
}

func (traces traceSlice) calcAverageWriteCountPerPage(largestAddress uint64) {
	count := make([]uint32, 1+(largestAddress>>9))
	for _, trace := range traces {
		if trace.Address != nil && trace.Rw != nil && *trace.Rw == pb.MemTrace_READ {
			count[*trace.Address>>9]++
		}
	}
	var total uint64
	for _, val := range count {
		total += uint64(val)
	}
}

func (traces traceSlice) findLargestMemAdress() uint64 {
	largest := uint64(0)
	for _, trace := range traces {
		if trace.Address != nil && *trace.Address > largest {
			largest = *trace.Address
		}
	}
	return largest
}
