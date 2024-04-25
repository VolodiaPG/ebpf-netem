package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	bar "github.com/schollz/progressbar"
)

// HANDLE_BPS map value struct
type handleBpsDelay struct {
	tcHandle        uint32
	throttleRateBps uint32
	delayMs         uint32
}

// parseIp parses IP address from string into uint32 (with reversed order)
func parseIpToLong(ip string) uint32 { // TODO: add error handling
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.LittleEndian, &long)
	return long
}

func fillMap(ebpfMap *ebpf.Map) {
	N := 65534 // fill map with N entries

	pbar := bar.New(N)
	start := time.Now()

	for i := 0; i < N; i++ {
		var handle_bps_delay handleBpsDelay
		index := int64(i + 2)
		ip_string := fmt.Sprintf("172.16.%d.%d", index/256, index%256)

		// set the same values for all entries for now
		handle_bps_delay.tcHandle = uint32(1)
		handle_bps_delay.throttleRateBps = 5000000
		handle_bps_delay.delayMs = uint32(i + 10)

		err := ebpfMap.Put(parseIpToLong(ip_string), handle_bps_delay)
		if err != nil {
			fmt.Println("err: putting ip and handle into map failed")
			fmt.Println(err)
			os.Exit(1)
		}
		pbar.Add(1)
	}
	elapsed := time.Since(start)
	fmt.Printf("\n\nTime elapsed for %d rules: %s\n", N, elapsed)
}

func main() {
	var unpinMapMode bool
	var delay_ms int
	var handle int
	var ip string
	var rate_bps int

	flag.BoolVar(&unpinMapMode, "unpin-map", false, "Unpins the map and exits.")
	flag.StringVar(&ip, "ip", "1.1.1.1", "Target IP to apply the filter for the egress")
	flag.IntVar(&handle, "handle", 0, "TC's handle")
	flag.IntVar(&rate_bps, "rate", 0, "Egress rate in BPS for the link.")
	flag.IntVar(&delay_ms, "delay", 0, "Egress delay in ms for the link.")

	flag.Parse()

	// Path to the map file of the eBPF program
	ebpfMapFile := "/sys/fs/bpf/IP_HANDLE_BPS_DELAY"

	// Load map
	ipHandleMap, err := ebpf.LoadPinnedMap(ebpfMapFile, &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Println("err: something went wrong with loading the pinned map")
		fmt.Println(err)
		os.Exit(1)
	}

	// Check if map should be unpinned
	if unpinMapMode {
		err = ipHandleMap.Unpin()
		if err != nil {
			fmt.Println("err: could not unpin map")
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Print map
	fmt.Printf("Loaded Map: %+v\n", ipHandleMap)

	// fill the map
	//fillMap(ipHandleMap)

	// Add another entry to the map to test overhead
	parsed_ip := parseIpToLong(ip)
	var handleBpsMapValue handleBpsDelay

	handleBpsMapValue.tcHandle = uint32(handle)
	handleBpsMapValue.throttleRateBps = uint32(rate_bps)
	handleBpsMapValue.delayMs = uint32(delay_ms)

	err = ipHandleMap.Put(parsed_ip, handleBpsMapValue)
	if err != nil {
		fmt.Println("err: putting ip and handle into map failed")
		fmt.Println(err)
		os.Exit(1)
	}
}
