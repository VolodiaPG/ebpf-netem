package main

import (
	"ebpf-network-simulator/pkg/utils"
	"flag"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go delay ebpf/ebpf_delay.c -- -I../headers

const (
	PIN_PATH = "/sys/fs/bpf/"
)

var (
	iface_name *string
)

func init() {
	iface_name = flag.String("iface", "eth0", "Interface to attach ebpf program to")
}

func main() {

	flag.Parse()

	objs := delayObjects{}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: PIN_PATH,
		},
	}

	if err := loadDelayObjects(&objs, &opts); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	progFd := objs.delayPrograms.TcMain.FD()
	iface, err := utils.GetIface(*iface_name)
	if err != nil {
		log.Fatalf("cannot find %s: %v", iface_name, err)
	}

	// Create clsact qdisc
	if _, err := utils.CreateClsactQdisc(iface); err != nil {
		log.Fatalf("cannot create clsact qdisc: %v", err)
	}

	// Create fq qdisc
	if _, err := utils.CreateFQdisc(iface); err != nil {
		log.Fatalf("cannot create fq qdisc: %v", err)
	}

	// Attach bpf program
	if _, err := utils.CreateTCBpfFilter(iface, progFd, netlink.HANDLE_MIN_EGRESS, "edt_bandwidth"); err != nil {
		log.Fatalf("cannot create bpf filter: %v", err)
	}

}
