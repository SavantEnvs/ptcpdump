package filter_expr

import (
	"github.com/jschwinger233/elibpcap"
)

// Fuzz drives the user-supplied pcap filter expression path (`ptcpdump 'tcp port 80'`):
// libpcap parses the expression to classic BPF and elibpcap translates it to eBPF for
// each program flavour ptcpdump injects it into (bpf/pcap_filter.go).
func Fuzz(data []byte) int {
	expr := string(data)
	if expr == "" {
		return -1
	}
	accepted := false
	for _, opts := range []elibpcap.Options{
		{AtBpf2Bpf: "pcap_filter", PacketAccessMode: elibpcap.Direct, L2Skb: true},
		{AtBpf2Bpf: "pcap_filter_l3", PacketAccessMode: elibpcap.Direct, L2Skb: false},
		{AtBpf2Bpf: "pcap_filter", PacketAccessMode: elibpcap.BpfProbeReadKernel, L2Skb: true},
		{AtBpf2Bpf: "pcap_filter", PacketAccessMode: elibpcap.BpfSkbLoadBytes, L2Skb: true},
	} {
		if _, err := elibpcap.CompileEbpf(expr, opts); err == nil {
			accepted = true
		}
	}
	if !accepted {
		return -1
	}
	return 1
}
