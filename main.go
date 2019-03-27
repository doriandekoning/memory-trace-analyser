package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"time"

	pb "github.com/doriandekoning/memory-trace-analyser/proto"
	"github.com/doriandekoning/memory-trace-analyser/statistics"

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
	curOffset := headerLength
	traceHeader := &pb.MemHeader{}
	nextMessagesize, n := proto.DecodeVarint(in[curOffset:])
	curOffset += n
	if err := proto.Unmarshal(in[curOffset:(curOffset+int(nextMessagesize))], traceHeader); err != nil {
		panic(err)
	}
	curOffset += int(nextMessagesize)

	traces := traceSlice{}
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
	reads, writes := traces.seperateReadWritesPerPage()
	fmt.Println("-----------------------\nTrace statistics:")
	fmt.Println("The trace was recorded at:", time.Unix(int64(traceHeader.GetTimestamp()), 0))
	fmt.Printf("The memory region for which the trace is recorded: [%#x,%#x]\n", traceHeader.MemoryRegion.GetStartAddr(), traceHeader.MemoryRegion.GetEndAddr())
	fmt.Printf("Clock frequency: %dGhz\n", traceHeader.GetTickFrequency()/uint64(math.Pow(10.0, 9.0)))
	fmt.Println("Amount of page reads: ", len(reads))
	fmt.Println("Amount of page writes:", len(writes))
	fmt.Println("Avg ticks between writes:", int(traces[len(traces)-1].GetCycle())/len(writes))
	fmt.Println("-----------------------")
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

func (traces traceSlice) seperateReadWritesPerPage() (reads, writes []uint64) {
	reads = []uint64{}
	writes = []uint64{}
	for _, traceEntry := range traces {
		if traceEntry.GetRw() == pb.MemTrace_READ {
			reads = append(reads, traceEntry.GetAddress()>>9)
		} else {
			writes = append(writes, traceEntry.GetAddress()>>9)
		}
	}
	return
}

func calculateStats(values []uint64, funcs []statistics.CalculateStatistic) {
	for _, val := range values {
		for _, f := range funcs {
			f(val)
		}
	}
}
