package main

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"compress/gzip"
	pb "github.com/doriandekoning/memory-trace-analyser/proto"
	"github.com/gogo/protobuf/proto"
	"strings"
)

const fileHeader = "gem5"
const readReq = 1
const writeReq = 4
const readExReq = 22
const writeBackDirty = 6
const writeClean = 8
const hardPFResp = 14

var totalBytesRead int

type traceSlice []*pb.Packet

type Input struct {
	in         *bufio.Reader
	nextPacket *pb.Packet
	buffer     []byte
}

type Stats struct {
	outside_region     uint64
	start_timestamp    uint64
	total_writes       uint64
	total_reads        uint64
	total_fetch        uint64
	min_addr           uint64
	max_addr           uint64
	addr_read_counts   map[uint64]uint64
	addr_write_counts  map[uint64]uint64
	addr_access_counts map[uint64]uint64
	addr_fetch_counts  map[uint64]uint64
	csvWriter          *csv.Writer
}

func main() {
	inputString := flag.String("input", "", "Comma separated input files")
	outputFile := flag.String("output", "output.csv", "Heatmap output")
	inputSource := flag.String("inputsource", "", "Input source gem5/qemu")
	gemTraceOut := flag.String("gemtraceout", "", "Gem trace ouput location for gem trace")
	// amountCpus := flag.Int("cpus", 1, "Amount of simulated cpus")
	flag.BoolVar(&debuggingEnabled, "debug", false, "If set to true additional debugging info will be logged")
	flag.Parse()
	inputFiles := strings.Split(*inputString, ",")

	file, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal("Unable to open input: ", err)
	}

	log.Print("Writing output to:", *outputFile)
	defer file.Close()

	var gemOutFile *os.File
	var gem5OutWriter *bufio.Writer
	log.Println("GEMOUT: ", *gemTraceOut)
	if gemTraceOut != nil && *gemTraceOut != "" {
		gemOutFile, err = os.Create(*gemTraceOut)
		if err != nil {
			log.Fatal("Unable to open qemu trace output file: ", err)
		}
		defer gemOutFile.Close()

		n, err := gemOutFile.Write([]byte("gem5"))
		if err != nil || n != 4 {
			log.Fatal("Unable to write file header", err)
		}
		tickFreq := uint64(1000000000000)
		objId := "objid"

		header := pb.PacketHeader{
			TickFreq: &tickFreq,
			ObjId:    &objId,
		}
		headerBytes, err := proto.Marshal(&header)
		if err != nil {
			log.Fatal("Unable to marshal header: ", err)
		}
		varint := proto.EncodeVarint(uint64(len(headerBytes)))
		log.Println("0:    ", gemOutFile)
		n, err = gemOutFile.Write(varint)
		if err != nil || n != len(varint) {
			log.Fatal("Unable to write header length")
		}
		n, err = gemOutFile.Write(headerBytes)
		if err != nil || n != len(headerBytes) {
			log.Fatal("Unable to write header")
		}
		log.Println("Setup gem output")
		gem5OutWriter = bufio.NewWriter(gemOutFile)
	}
	outWriter := csv.NewWriter(file)
	stats := Stats{
		addr_read_counts:   map[uint64]uint64{},
		addr_write_counts:  map[uint64]uint64{},
		addr_access_counts: map[uint64]uint64{},
		addr_fetch_counts:  map[uint64]uint64{},
		csvWriter:          outWriter,
	}
	stats.csvWriter.Write([]string{"timestamp", "total_accesses", "total_reads", "total_writes", "total_pages_accessed", "total_pages_written", "total_pages_read", "total_pages_fetched"})
	stats.csvWriter.Write([]string{"0", "0", "0", "0", "0", "0", "0", "0"})

	Debugf("Using input files located at: '%v' for inputsource: %s", inputFiles, *inputSource)
	if *inputSource == "qemu" {
		log.Printf("Reading qemu trace")
		processQemuTrace(inputFiles[0], &stats, gem5OutWriter)
	} else if *inputSource == "gem5" {
		log.Printf("Reading gem5 trace")
		processGem5Trace(inputFiles, &stats)
	} else {
		log.Fatal("Unknown input source")
	}
}

func processGem5Trace(paths []string, stats *Stats) {
	inputs := []Input{}
	for _, path := range paths {
		var in *bufio.Reader
		var err error
		file, err := os.Open(path)
		if err != nil {
			log.Fatal("Unable to open input: ", err)
		}
		if strings.HasSuffix(path, ".gz") {
			log.Print("Input file is gz")
			gz, err := gzip.NewReader(file)
			if err != nil {
				log.Fatal("Unable to open gzip file:", err)
			}
			defer gz.Close()
			in = bufio.NewReader(gz)
		} else {
			in = bufio.NewReader(file)
		}
		inBuf := make([]byte, 4)
		n, err := io.ReadFull(in, inBuf)
		if err != nil || n != len(inBuf) {
			panic("Unable to read header")
		}
		header := string(inBuf)
		if header != fileHeader {
			panic("Input not recognized")
		}
		traceHeader := &pb.PacketHeader{}
		nextMessagesize, err := getNextPackageLength(in)
		if err != nil {
			panic(err)
		}

		inBuf = make([]byte, nextMessagesize)
		n, err = io.ReadFull(in, inBuf)
		if err != nil || n != int(nextMessagesize) {
			panic("Unable to read bytes for traceheader")
		}
		err = proto.Unmarshal(inBuf, traceHeader)
		if err != nil {
			panic(fmt.Errorf("Unable to unmarshal trace header, %w", err))
		}
		inputs = append(inputs, Input{
			in:     in,
			buffer: make([]byte, 1024),
		})

		log.Println("TRACEHEADER:", *traceHeader)
		log.Println("Tick frequency:", *traceHeader.TickFreq)
		log.Println("Objid:", *traceHeader.ObjId)
	}

	var startTick, curTick uint64

outer:
	for true {
		// Find next packet
		smallestTickIdx := 0
		for idx := range inputs {
			if inputs[idx].nextPacket == nil {
				inputs[idx].nextPacket = &pb.Packet{}
				err := inputs[idx].getNextPacket()
				if err != nil {
					fmt.Println("Error while getting next packet: %v", err)
					break outer
				}
			}
			if inputs[idx].nextPacket.GetTick() <= inputs[smallestTickIdx].nextPacket.GetTick() {
				smallestTickIdx = idx
			}
		}
		packet := inputs[smallestTickIdx].nextPacket
		if startTick == 0 {
			startTick = packet.GetTick()
		}
		curTick = packet.GetTick() - startTick
		stats.processAccess(packet.GetAddr(), packet.GetTick()-startTick, isWrite(packet.GetCmd()), smallestTickIdx == 1)

		err := inputs[smallestTickIdx].getNextPacket()
		if err != nil {
			fmt.Println("Unable to get next packet: %v", err)
			break
		}
	}
	stats.flush(curTick)
	stats.print()
}

func (i *Input) getNextPacket() error {
	nextMessagesize, err := getNextPackageLength(i.in)
	if err != nil {
		return fmt.Errorf("End of file found: %w", err)
	}
	inBytes := i.buffer[:nextMessagesize]
	n, err := io.ReadFull(i.in, inBytes)
	if err != nil || n != int(nextMessagesize) {
		return fmt.Errorf("Unable to read next packet: %w", err)
	}
	err = proto.Unmarshal(inBytes, i.nextPacket)
	if err != nil {
		return fmt.Errorf("Unable to unmarshal: %w", err)
	}
	inBytes = nil
	return nil
}

func processQemuTrace(path string, stats *Stats, gemOutWriter *bufio.Writer) {
	memranges := [][]uint64{
		{0, 0xc0000000},
		{0x100000000, 0x240000000},
	}

	file, err := os.Open(path)
	if err != nil {
		log.Fatal("Unable to open input: ", err)
	}
	bufioReader := bufio.NewReader(file)
	// prevT := uint64(0)
	cur_timestamp := uint64(0)
	packetSize := uint32(8)
	writeReqUint := uint32(writeReq)
	readReqUint := uint32(readReq)
	for {
		//addr :=
		addr, err := readInt64(bufioReader)
		if err != nil {
			log.Println("err:", err)
			break
		}
		cur_timestamp, err = readInt64(bufioReader)
		if err != nil {
			log.Println("err:", err)
			break
		}
		t, err := readInt8(bufioReader)
		if err != nil {
			log.Println("err:", err)
			break
		}
		//size? :=
		_, err = readInt8(bufioReader)
		if err != nil {
			log.Println("err:", err)
			break
		}
		if addr > memranges[0][1] && (addr < memranges[1][0] || addr > memranges[1][1]) {
			stats.outside_region++
			continue
		}
		stats.processAccess(addr, cur_timestamp, t == 2, t == 3)

		if gemOutWriter != nil {
			packet := pb.Packet{
				Tick: &cur_timestamp,
				Addr: &addr,
				Size: &packetSize, //TODO check bits or bytes
			}
			if t == 2 {
				packet.Cmd = &writeReqUint
			} else {
				packet.Cmd = &readReqUint
			}

			writePacket(gemOutWriter, &packet)
		}
	}
	if gemOutWriter != nil {
		gemOutWriter.Flush()
	}
	stats.flush(cur_timestamp)
	stats.print()

}

func (s *Stats) processAccess(addr uint64, timestamp uint64, write bool, fetch bool) {
	s.addr_access_counts[addr>>12]++

	if s.start_timestamp == 0 {
		s.start_timestamp = timestamp
	}
	if write {
		s.addr_write_counts[addr>>12]++
		s.total_writes++
	} else {
		if fetch {
			s.total_fetch++
			s.addr_fetch_counts[addr>>12]++
		} else {
			s.total_reads++
			s.addr_read_counts[addr>>12]++
		}
	}
	total := s.total_writes + s.total_reads + s.total_fetch
	if total > 0 && total%10000000 == 0 {
		log.Printf("Processed: %d million accesses\n", total/1000000)
		log.Println("Total bytes read:", totalBytesRead)
		log.Println("Total pages accessed: ", len(s.addr_access_counts))
		if total == 1000000000 {
			s.flush(timestamp - s.start_timestamp)
		} else {
			s.writeOut(timestamp - s.start_timestamp)
		}
		s.print()
	}

}

func (s *Stats) flush(timestamp uint64) {
	s.writeOut(timestamp)
	s.csvWriter.Flush()
}

func (s *Stats) writeOut(timestamp uint64) {
	s.csvWriter.Write([]string{
		strconv.Itoa(int(timestamp)),                                      // Timestamp
		strconv.Itoa(int(s.total_reads + s.total_writes + s.total_fetch)), // Total writes
		strconv.Itoa(int(s.total_reads)),                                  // Total reads
		strconv.Itoa(int(s.total_writes)),                                 //Total writes
		strconv.Itoa(len(s.addr_access_counts)),                           // Total pages accessed
		strconv.Itoa(len(s.addr_write_counts)),                            // Total pages written
		strconv.Itoa(len(s.addr_read_counts)),                             // Total pages read
		strconv.Itoa(len(s.addr_fetch_counts)),                            // Total fetch counts
	})
}

func readInt64(reader io.Reader) (uint64, error) {
	totalRead := 0
	b := make([]byte, 8)
	for totalRead < 8 {
		n, err := reader.Read(b[totalRead:])
		if err != nil {
			return 0, fmt.Errorf("Unable to read bytes for uint64 from file: %w", err)
		}
		totalRead += n
	}
	totalBytesRead += 8
	return binary.LittleEndian.Uint64(b), nil
}

func readInt8(reader io.Reader) (uint8, error) {
	b := make([]byte, 1)
	n, err := reader.Read(b)
	if err != nil || n != len(b) {
		log.Println("Read:", n, " but wanted: ", len(b))
		return 0, fmt.Errorf("Unable to read bytes for uint8 from file: %w", err)
	}
	totalBytesRead += 1
	return uint8(b[0]), nil
}

func writePacket(writer io.Writer, pkt *pb.Packet) {
	packetBytes, err := proto.Marshal(pkt)
	if err != nil {
		log.Fatal("Unable to marshal packet!")
	}
	lenBytes := proto.EncodeVarint(uint64(len(packetBytes)))
	for bytesWritten := 0; bytesWritten < len(lenBytes); bytesWritten += 0 {
		n, err := writer.Write(lenBytes)
		if err != nil {
			log.Fatal("Unable to write packet length: ", err)
		}
		bytesWritten += n
	}
	for bytesWritten := 0; bytesWritten < len(packetBytes); bytesWritten += 0 {
		n, err := writer.Write(packetBytes)
		if err != nil || n != len(packetBytes) {
			log.Fatal("Unable to write packet: ", err)
		}
		bytesWritten += n
	}
}

func (s *Stats) print() {
	log.Printf("Total accessses:\t\t%d\n", s.total_reads+s.total_writes+s.total_fetch)
	log.Printf("Total reads: 	\t%d\n", s.total_reads)
	log.Printf("Total writes:	\t%d\n", s.total_writes)
	log.Printf("Total fetch: \t\t%d\n", s.total_fetch)
	log.Printf("Ratio:\t\t	 %f\n", float64(s.total_writes)/float64(s.total_reads))
	log.Printf("Pages amount:\t\t%d\n", len(s.addr_access_counts))
	log.Printf("Outside region:\t\t%d\n", s.outside_region)
}

func (s *Stats) calcMinMax() {
	s.min_addr = 1 << 63
	s.max_addr = 0
	for k := range s.addr_access_counts {
		if k < s.min_addr {
			s.min_addr = k
		}
		if k > s.max_addr {
			s.max_addr = k
		}
	}
	log.Printf("Min:%x, max:%x\n", s.min_addr, s.max_addr)
}

func (s *Stats) outputHeatmapCSV(xval uint64, csvWriter *csv.Writer) {
	for k, v := range s.addr_access_counts {
		csvWriter.Write([]string{
			strconv.Itoa(int(xval)),
			strconv.Itoa(int(k << 12)),
			strconv.Itoa(int(v)),
		})
	}
	csvWriter.Flush()

}

func getNextPackageLength(in *bufio.Reader) (uint64, error) {
	var n int = 0
	var read []byte
	var err error
	for n < 8 {
		read, err = in.Peek(8)
		if err != nil {
			return 0, fmt.Errorf("Unable to read package length: %w", err)
		}
		n += len(read)
	}

	nextMessagesize, n := proto.DecodeVarint(read)
	if n == 0 {
		panic("Unable to read varint")
	}
	nDiscarded, err := in.Discard(n)
	if err != nil || n != nDiscarded {
		panic("Unable to discard ")
	}
	totalBytesRead += n + int(nextMessagesize)
	return nextMessagesize, nil
}

func isWrite(cmd uint32) bool {
	if cmd == readReq || cmd == readExReq || cmd == hardPFResp {
		return false
	} else if cmd == writeBackDirty || cmd == writeClean || cmd == writeReq {
		return true
	} else if cmd != 19 && cmd != 9 {
		log.Println("Unknown event:", cmd)
	}
	return false
}
