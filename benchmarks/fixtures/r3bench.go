package main

import (
	"fmt"
	"sort"
)

var markerA = "RADARE3_SEARCH_MARKER_ALPHA"
var markerB = "RADARE3_SEARCH_MARKER_BETA"
var wideMarker = []uint16{
	'R', 'A', 'D', 'A', 'R', 'E', '3', '_', 'W', 'I', 'D', 'E', '_', 'M', 'A', 'R', 'K', 'E', 'R', 0,
}

//go:noinline
func mix(value uint64) uint64 {
	for i := uint64(0); i < 56; i++ {
		if (value^i)&1 == 1 {
			value = (value * 0x9e3779b185ebca87) ^ (value >> 7)
		} else {
			value = (value + 0x517cc1b727220a95) ^ (value << 11)
		}
	}
	return value
}

//go:noinline
func fanout(value uint64) uint64 {
	switch value & 7 {
	case 0:
		return mix(value + 2)
	case 1:
		return mix(value + 6)
	case 2:
		return mix(value + 10)
	case 3:
		return mix(value + 14)
	case 4:
		return mix(value + 18)
	case 5:
		return mix(value + 22)
	case 6:
		return mix(value + 26)
	default:
		return mix(value + 30)
	}
}

//go:noinline
func drain(work <-chan uint64, out chan<- uint64) {
	acc := uint64(0)
	for v := range work {
		acc ^= fanout(v)
	}
	out <- acc
}

func main() {
	work := make(chan uint64, 64)
	out := make(chan uint64, 4)

	for w := 0; w < 4; w++ {
		go drain(work, out)
	}

	go func() {
		for i := uint64(0); i < 768; i++ {
			work <- i*2654435761 + 1
		}
		close(work)
	}()

	partials := make([]uint64, 0, 4)
	for i := 0; i < 4; i++ {
		partials = append(partials, <-out)
	}
	sort.Slice(partials, func(i, j int) bool { return partials[i] < partials[j] })

	acc := uint64(0)
	for _, p := range partials {
		acc ^= mix(p)
	}
	acc += uint64(markerA[0]) + uint64(markerB[1]) + uint64(wideMarker[2])

	fmt.Println(acc)
}
