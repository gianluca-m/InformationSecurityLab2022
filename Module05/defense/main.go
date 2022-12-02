package main

import (
	"log"
	"time"

	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"
)

const (
	SMALL_TIMEOUT    = time.Second
	LARGE_TIMEOUT    = 300 * time.Second
	IA_TIMEOUT       = 5 * time.Second
	SRC_ADDR_TIMEOUT = 14 * time.Second
)

type PacketInfo struct {
	ArrivalTime time.Time
	Count       int
	Finished    bool
	Src         string
	Dest        string
}

var (
	first                  = true
	last_call              time.Time
	srcLocations           map[string]PacketInfo = make(map[string]PacketInfo)
	FinishedPacketSrcAddrs map[string]PacketInfo = make(map[string]PacketInfo)
	FinishedPacketIAs      map[string]PacketInfo = make(map[string]PacketInfo)
)

func filter1(scion slayers.SCION) bool {
	currIA := scion.SrcIA.String()

	srcAddr, err := scion.SrcAddr()
	if err != nil {
		log.Fatal(err)
	}
	currIASrcAddr := currIA + "--" + srcAddr.String()

	if SMALL_TIMEOUT < time.Since(last_call) {
		for ia, packet := range FinishedPacketIAs {
			if !packet.Finished {
				delete(FinishedPacketIAs, ia)
			}
		}
		for addr, packet := range FinishedPacketSrcAddrs {
			if !packet.Finished {
				delete(FinishedPacketSrcAddrs, addr)
			}
		}
		last_call = time.Now()
	}

	IA_packet, IA_exists := FinishedPacketIAs[currIA]
	if !IA_exists {
		FinishedPacketIAs[currIA] = PacketInfo{Count: 1, Finished: false}
	} else {
		if !FinishedPacketSrcAddrs[currIASrcAddr].Finished {
			IA_packet.Count++
			FinishedPacketIAs[currIA] = IA_packet
		} else if 14 < IA_packet.Count {
			IA_packet.Finished = true
			FinishedPacketIAs[currIA] = IA_packet
		}
	}

	IASrcAddr_packet, IASrcAddr_exists := FinishedPacketSrcAddrs[currIASrcAddr]
	if !IASrcAddr_exists {
		FinishedPacketSrcAddrs[currIASrcAddr] = PacketInfo{ArrivalTime: time.Now().Add(LARGE_TIMEOUT), Count: 1, Finished: false}
	} else {
		if IASrcAddr_packet.Finished && SRC_ADDR_TIMEOUT < time.Since(IASrcAddr_packet.ArrivalTime) {
			delete(FinishedPacketSrcAddrs, currIASrcAddr)
		} else if IASrcAddr_packet.Count <= 3 {
			IASrcAddr_packet.Count++
			FinishedPacketSrcAddrs[currIASrcAddr] = IASrcAddr_packet
		} else {
			IASrcAddr_packet.ArrivalTime = time.Now()
			IASrcAddr_packet.Finished = true
			FinishedPacketSrcAddrs[currIASrcAddr] = IASrcAddr_packet
		}
	}

	return !(FinishedPacketIAs[currIA].Finished || FinishedPacketSrcAddrs[currIASrcAddr].Finished)
}

func filter2(scion slayers.SCION) bool {
	srcAddr, err := scion.SrcAddr()
	if err != nil {
		log.Fatal(err)
	}

	srcLocation := scion.SrcIA.A.String() + srcAddr.String()

	if first && srcLocations[srcLocation].Count < 1 {
		return false
	}
	srcLocationInfo, _ := srcLocations[srcLocation]
	srcLocationInfo.Count++

	if 50 > srcLocationInfo.Count {
		return true
	}

	first = false
	return false
}

// This function receives all packets destined to the customer server.
//
// Your task is to decide whether to forward or drop a packet based on the
// headers and payload.
// References for the given packet types:
// - SCION header
//   https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#SCION
// - UDP header
//   https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#UDP
//
func filter(scion slayers.SCION, udp slayers.UDP, payload []byte) bool {
	res1 := filter1(scion)
	res2 := filter2(scion)

	if res1 {
		return true
	} else if res1 == res2 {
		return res1
	} else {
		return false
	}
}

func init() {
	// Perform any initial setup here
}

func main() {
	// Start the firewall. Code after this line will not be executed
	lib.RunFirewall(filter)
}
