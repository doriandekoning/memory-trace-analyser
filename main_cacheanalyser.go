package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

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
const cleanEvict = 9
const upgradeResp = 19
const hardPFResp = 14

var totalBytesRead int
var amountUnknownCmd int

type traceSlice []*pb.Packet

type Input struct {
	in         *bufio.Reader
	nextPacket *pb.Packet
	buffer     []byte
}

func main() {
	inputString := flag.String("input", "", "Comma separated input files")
	qemuTraceOut := flag.String("out", "", "Gem trace ouput location for qemu trace")
	flag.Parse()
	inputFiles := strings.Split(*inputString, ",")

	log.Println("Writing output to: ", *qemuTraceOut)
	output, err := os.Create(*qemuTraceOut)
	if err != nil {
		log.Fatal("Unable to open output: ", err)
	}

	log.Print("Writing output to:", *qemuTraceOut)
	defer output.Close()

	bufferedOutput := bufio.NewWriter(output)

	log.Printf("Reading gem5 trace")
	processGem5Trace(inputFiles, bufferedOutput)
}

func processGem5Trace(paths []string, out io.Writer) {
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
		log.Printf("%d:%s\n", len(inputs), path)
		inputs = append(inputs, Input{
			in:     in,
			buffer: make([]byte, 1024),
		})

		log.Println("Tick frequency:", *traceHeader.TickFreq)
		log.Println("Objid:", *traceHeader.ObjId)
	}

	var startTick uint64

	i := 0
	mpki := 0
	mpki_write := 0
	mpki_read := 0

	readMiss := 0
	writeMiss := 0
	nines := 0
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
		// log.Printf("%x,%x,%d\n", packet.GetTick(), packet.GetAddr(), smallestTickIdx)
		if smallestTickIdx == 0 {
			write, err := isWrite(packet.GetCmd())
			if err == nil {
				mpki++
				if write {
					mpki_write++
					writeMiss++
				} else {
					readMiss++
					mpki_read++
				}
			}
		} else {
			i++
			// if packet.GetCmd() != 9 {
			// 	i++
			writeQemuEvent(packet, out, uint8((smallestTickIdx-1)/2), smallestTickIdx%2 == 1)
			// }else{
			// 	nines++
			// }

			if i%10000000 == 0 {
				fmt.Printf("%d,%d,0,%d,%d\n", i/1000000, mpki, mpki_read, mpki_write)
				mpki = 0
				mpki_read = 0
				mpki_write = 0
			}
		}
		if i == 5000000000 {
			break
		}

		err := inputs[smallestTickIdx].getNextPacket()
		if err != nil {
			fmt.Println("Unable to get next packet: %v", err)
			break
		}
	}
	fmt.Printf("Nines:%d\n", nines)
	fmt.Println("Read miss:", readMiss)
	fmt.Println("Write miss:", writeMiss)
}

func writeQemuEvent(packet *pb.Packet, out io.Writer, cpu uint8, fetch bool) {
	accessType := uint8(1)
	write, err := isWrite(packet.GetCmd())
	if err != nil {
		return
	}
	if fetch {
		accessType = 2
	} else if write {
		accessType = 1
	} else {
		accessType = 0
	}

	err = binary.Write(out, binary.LittleEndian, packet.Tick)
	if err != nil {
		log.Fatal(err)
	}
	err = binary.Write(out, binary.LittleEndian, packet.Addr)
	if err != nil {
		log.Fatal(err)
	}
	err = binary.Write(out, binary.LittleEndian, accessType)
	if err != nil {
		log.Fatal(err)
	}

	err = binary.Write(out, binary.LittleEndian, cpu)
	if err != nil {
		log.Fatal(err)
	}
}

func isWrite(cmd uint32) (bool, error) {
	if cmd == readReq || cmd == readExReq || cmd == hardPFResp {
		return false, nil
	} else if cmd == writeBackDirty || cmd == writeReq { // || cmd == writeClean {
		return true, nil
	} else if cmd != 19 && cmd != 9 && cmd != 8 {
		log.Println("Unknown event:", cmd)
	} else {
		amountUnknownCmd++
		/*		if amountUnknownCmd > 1000000 {
				fmt.Printf("%d unknonw\n", amountUnknownCmd)
			}*/
	}
	return false, fmt.Errorf("Not found")
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

// func readInt64(reader io.Reader) (uint64, error) {
// 	totalRead := 0
// 	b := make([]byte, 8)
// 	for totalRead < 8 {
// 		n, err := reader.Read(b[totalRead:])
// 		if err != nil {
// 			return 0, fmt.Errorf("Unable to read bytes for uint64 from file: %w", err)
// 		}
// 		totalRead += n
// 	}
// 	totalBytesRead += 8
// 	return binary.LittleEndian.Uint64(b), nil
// }

// func readInt8(reader io.Reader) (uint8, error) {
// 	b := make([]byte, 1)
// 	n, err := reader.Read(b)
// 	if err != nil || n != len(b) {
// 		log.Println("Read:", n, " but wanted: ", len(b))
// 		return 0, fmt.Errorf("Unable to read bytes for uint8 from file: %w", err)
// 	}
// 	totalBytesRead += 1
// 	return uint8(b[0]), nil
// }

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
