package proxyProtocol

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
)

var (
	fixtureTCP4 = "PROXY TCP4 127.0.0.1 127.0.0.1 65533 65533\r\n"
	fixtureTCP6 = "PROXY TCP6 2001:4801:7817:72:d4d9:211d:ff10:1631 2001:4801:7817:72:d4d9:211d:ff10:1631 65533 65533\r\n"

	fixtureTCP4V2 = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\x7F\x00\x00\x01\x7F\x00\x00\x01\xFF\xFD\xFF\xFD"
	fixtureTCP6V2 = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x12\x00\x24\x20\x01\x48\x01\x78\x17\x00\x72\xD4\xD9\x21\x1D\xFF\x10\x16\x31\x20\x01\x48\x01\x78\x17\x00\x72\xD4\xD9\x21\x1D\xFF\x10\x16\x31\xFF\xFD\xFF\xFD"

	v4addr, _ = net.ResolveIPAddr("ip", "127.0.0.1")
	v6addr, _ = net.ResolveIPAddr("ip", "2001:4801:7817:72:d4d9:211d:ff10:1631")
	pTCP4     = &ProxyLine{
		Protocol: TCP4,
		SrcAddr: &net.TCPAddr{
			IP:   v4addr.IP,
			Port: 65533,
		},
		DstAddr: &net.TCPAddr{
			IP:   v4addr.IP,
			Port: 65533,
		},
	}
	pTCP6 = &ProxyLine{
		Protocol: TCP6,
		SrcAddr: &net.TCPAddr{
			IP:   v6addr.IP,
			Port: 65533,
		},
		DstAddr: &net.TCPAddr{
			IP:   v6addr.IP,
			Port: 65533,
		},
	}

	invalidProxyLines = []string{
		"PROXY TCP4 127.0.0.1 127.0.0.1 65533 65533", // no CRLF
		"PROXY \r\n", // not enough fields
		"PROXY TCP6 127.0.0.1 127.0.0.1 65533 65533\r\n,",                                                        // unmatched protocol addr
		"PROXY TCP4 2001:4801:7817:72:d4d9:211d:ff10:1631 2001:4801:7817:72:d4d9:211d:ff10:1631 65533 65533\r\n", // unmatched protocol addr
		"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A",                                                       // not enough fields
		"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\xFF\x00",                                           // wrong addrprotocol
		"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x23\x11\x00",                                           // wrong command
		"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x13\x11\x00",                                           // wrong version
	}
	noneProxyLine = "There is no spoon."
)

func TestParseTCP4(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(fixtureTCP4))
	p, err := ConsumeProxyLine(reader)
	fmt.Printf("%v", p)
	if err != nil {
		t.Fatalf("Parsing TCP4 failed: %v\n", err)
	}
	if !p.EqualTo(pTCP4) {
		t.Fatalf("Expected ProxyLine %v, got %v\n", pTCP4, p)
	}
}

func TestParseTCP6(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(fixtureTCP6))
	p, err := ConsumeProxyLine(reader)
	fmt.Printf("%v", p)
	if err != nil {
		t.Fatalf("Parsing TCP6 failed: %v\n", err)
	}
	if !p.EqualTo(pTCP6) {
		t.Fatalf("Expected ProxyLine %v, got %v\n", pTCP6, p)
	}
}

func TestParseTCP4V2(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(fixtureTCP4V2))
	p, err := ConsumeProxyLine(reader)
	fmt.Printf("%v", p)
	if err != nil {
		t.Fatalf("Parsing TCP4V2 failed: %v\n", err)
	}
	if !p.EqualTo(pTCP4) {
		t.Fatalf("Expected ProxyLineV2 %v, got %v\n", pTCP4, p)
	}
}

func TestParseTCP6V2(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(fixtureTCP6V2))
	p, err := ConsumeProxyLine(reader)
	fmt.Printf("%v", p)
	if err != nil {
		t.Fatalf("Parsing TCP6V2 failed: %v\n", err)
	}
	if !p.EqualTo(pTCP6) {
		t.Fatalf("Expected ProxyLineV2 %v, got %v\n", pTCP6, p)
	}
}

func TestParseNonProxyLine(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(noneProxyLine))
	p, err := ConsumeProxyLine(reader)
	if err != nil || p != nil {
		t.Fatalf("Parsing none PROXY line failed. Expected nil, nil; got %q, %q\n", p, err)
	}
}

func TestInvalidProxyLines(t *testing.T) {
	for _, str := range invalidProxyLines {
		reader := bufio.NewReader(strings.NewReader(str))
		_, err := ConsumeProxyLine(reader)
		if err == nil {
			t.Fatalf("Parsing an invalid PROXY line %q fails to fail\n", str)
		}
	}
}

func (p *ProxyLine) EqualTo(q *ProxyLine) bool {
	return p.Protocol == q.Protocol &&
		p.SrcAddr.String() == q.SrcAddr.String() &&
		p.DstAddr.String() == q.DstAddr.String()
}
