//go:build !linux && !darwin

package sys

import (
	"github.com/shirou/gopsutil/net"
)

// The panel targets Linux; these gopsutil-backed fallbacks exist so the whole
// module still builds and its tests still run on other platforms during
// development.

func GetTCPCount() (int, error) {
	stats, err := net.Connections("tcp")
	if err != nil {
		return 0, err
	}
	return len(stats), nil
}

func GetUDPCount() (int, error) {
	stats, err := net.Connections("udp")
	if err != nil {
		return 0, err
	}
	return len(stats), nil
}
