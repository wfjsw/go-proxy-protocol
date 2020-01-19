/**
 *  Copyright 2013 Rackspace
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Packet proxyProtocol implements Proxy Protocol parser and writer.
package proxyProtocol

import (
    "bufio"
    "bytes"
    "errors"
    "fmt"
    "io"
    "net"
    "strconv"
    "strings"
    "encoding/binary"
)

// INET protocol and family
const (
    TCP4    = "tcp4"    // TCP over IPv4
    TCP6    = "tcp6"    // TCP over IPv6
    UDP4    = "udp4"    // UDP over IPv4
    UDP6    = "udp6"    // UDP over IPv6
    UNIXSTREAM  = "unix"
    UNIXDGRAM   = "unixgram"
    UNKNOWN = "unknown" // Unsupported or unknown protocols
)

var (
    InvalidProxyLine   = errors.New("Invalid proxy line")
    InvalidProtocol    = errors.New("Invalid Address Family or Protocol")
    UnmatchedIPAddress = errors.New("IP address(es) unmatched with protocol")
    InvalidPortNum     = errors.New(fmt.Sprintf("Invalid port number parsed. (expected [%d..%d])", _port_lower, _port_upper))
)

var (
    _proxyV1    = []byte{'P', 'R', 'O', 'X', 'Y'}
    _proxyV2    = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A }
    _CRLF       = "\r\n"
    _sep        = " "
    _port_lower = 0
    _port_upper = 65535
    _cmdLocal   = 0
    _cmdProxy   = 1
)

type ProxyLine struct {
    Protocol string
    SrcAddr  net.Addr
    DstAddr  net.Addr
}

// ConsumeProxyLine looks for PROXY line in the reader and try to parse it if found.
//
// If first 5 bytes in reader is "PROXY", the function reads one line (until first '\n') from reader and try to parse it as ProxyLine. A newly allocated ProxyLine is returned if parsing secceeds. If parsing fails, a nil and an error is returned;
//
// If first 5 bytes in reader is not "PROXY", the function simply returns (nil, nil), leaving reader intact (nothing from reader is consumed).
//
// If the being parsed PROXY line is using an unknown protocol, ConsumeProxyLine parses remaining fields as same syntax as a supported protocol assuming IP is used in layer 3, and reports error if failed.
func ConsumeProxyLine(reader *bufio.Reader) (*ProxyLine, error) {
    bin, _ := reader.Peek(12)
    if bytes.Equal(bin, _proxyV2) {
        return consumeProxyLineV2(reader)
    }
    word, _ := reader.Peek(5)
    if bytes.Equal(word, _proxyV1) {
        return consumeProxyLineV1(reader)
    }
    return nil, nil
}

func consumeProxyLineV1(reader *bufio.Reader) (*ProxyLine, error) {
    line, err := reader.ReadString('\n')
    if !strings.HasSuffix(line, _CRLF) {
        return nil, InvalidProxyLine
    }
    tokens := strings.Split(line[:len(line)-2], _sep)
    ret := new(ProxyLine)
    if len(tokens) < 6 {
        return nil, InvalidProxyLine
    }
    switch strings.ToLower(tokens[1]) {
        case TCP4: ret.Protocol = TCP4
        case TCP6: ret.Protocol = TCP6
        default: ret.Protocol = UNKNOWN
    }
    ret.SrcAddr, err = parseIPAddr(ret.Protocol, net.JoinHostPort(tokens[2], tokens[4]))
    if err != nil {
        return nil, err
    }
    ret.DstAddr, err = parseIPAddr(ret.Protocol, net.JoinHostPort(tokens[3], tokens[5]))
    if err != nil {
        return nil, err
    }
    return ret, nil
}

func consumeProxyLineV2(reader *bufio.Reader) (*ProxyLine, error) {
    reader.Discard(12)
    ret := new(ProxyLine)

    vercmd, err := reader.ReadByte()
    if err != nil {
        return nil, err
    } 
    ver := vercmd >> 4
    cmd := vercmd & 0x0f
    if ver != 2 {
        return nil, InvalidProxyLine
    }
    var isLocal bool
    switch int(cmd) {
        case _cmdLocal: isLocal = true
        case _cmdProxy: isLocal = false
        default: return nil, InvalidProxyLine
    }

    afptc, err := reader.ReadByte()
    if err != nil {
        return nil, err
    }
    switch int(afptc) {
        case 0x00: ret.Protocol = UNKNOWN
        case 0x11: ret.Protocol = TCP4
        case 0x12: ret.Protocol = TCP6
        case 0x21: ret.Protocol = UDP4
        case 0x22: ret.Protocol = UDP6
        case 0x31: ret.Protocol = UNIXSTREAM
        case 0x32: ret.Protocol = UNIXDGRAM
        default: return nil, InvalidProtocol 
    }

    lenb := make([]byte, 2)
    _, err = io.ReadFull(reader, lenb)
    if err != nil && err != io.EOF {
        return nil, err
    }
    len := binary.BigEndian.Uint16(lenb)

    if isLocal {
        reader.Discard(int(len))
        return nil, nil
    }

    if len > 0 {
        payload := make([]byte, len)
        _, err := io.ReadFull(reader, payload)
        if err != nil && err != io.EOF {
            return nil, err
        }

        if ret.Protocol == TCP4 || ret.Protocol == UDP4 || ret.Protocol == TCP6 || ret.Protocol == UDP6 {
            var src_ip, dst_ip net.IP
            var src_port, dst_port int
            
            if ret.Protocol == TCP4 || ret.Protocol == UDP4 {
                src_ip = net.IP(payload[:4])
                dst_ip = net.IP(payload[4:8])
                src_port = int(binary.BigEndian.Uint16(payload[8:10]))
                dst_port = int(binary.BigEndian.Uint16(payload[10:12]))
            } else if ret.Protocol == TCP6 || ret.Protocol == UDP6 {
                src_ip = net.IP(payload[:16])
                dst_ip = net.IP(payload[16:32])
                src_port = int(binary.BigEndian.Uint16(payload[32:34]))
                dst_port = int(binary.BigEndian.Uint16(payload[34:36]))
            } else {
                return nil, InvalidProxyLine
            }

            if ret.Protocol == TCP4 || ret.Protocol == TCP6 {
                ret.SrcAddr = &net.TCPAddr{
                    IP: src_ip,
                    Port: src_port,
                }
                ret.DstAddr = &net.TCPAddr{
                    IP: dst_ip,
                    Port: dst_port,
                }
            } else if ret.Protocol == UDP4 || ret.Protocol == UDP6 {
                ret.SrcAddr = &net.UDPAddr{
                    IP: src_ip,
                    Port: src_port,
                }
                ret.DstAddr = &net.UDPAddr{
                    IP: dst_ip,
                    Port: dst_port,
                }
            } else {
                return nil, InvalidProxyLine
            }
        } else if ret.Protocol == UNIXSTREAM || ret.Protocol == UNIXDGRAM {
            src_addr := string(payload[:108])
            dst_addr := string(payload[108:216])
            ret.SrcAddr, err = net.ResolveUnixAddr(ret.Protocol, src_addr)
            if err != nil {
                return nil, err
            }
            ret.DstAddr, err = net.ResolveUnixAddr(ret.Protocol, dst_addr)
            if err != nil {
                return nil, err
            }
        }
    }

    // TODO: additional field

    return ret, err

}

// WriteProxyLine formats p as valid PROXY line into w
func (p *ProxyLine) WriteProxyLine(w io.Writer) (err error) {
    _, err = fmt.Fprintf(w, "PROXY %s %s %s %d %d\r\n", strings.ToUpper(p.Protocol), p.SrcAddr.(*net.TCPAddr).IP.String(), p.DstAddr.(*net.TCPAddr).IP.String(), p.SrcAddr.(*net.TCPAddr).Port, p.DstAddr.(*net.TCPAddr).Port)
    return
}

func parsePortNumber(portStr string) (port int, err error) {
    port, err = strconv.Atoi(portStr)
    if err == nil {
        if port < _port_lower || port > _port_upper {
            err = InvalidPortNum
        }
    }
    return
}

func parseIPAddr(protocol string, addrStr string) (addr net.Addr, err error) {
    proto := "tcp"
    if protocol == TCP4 {
        proto = "tcp4"
    } else if protocol == TCP6 {
        proto = "tcp6"
    }
    addr, err = net.ResolveTCPAddr(proto, addrStr)
    if err == nil {
        tryV4 := addr.(*net.TCPAddr).IP.To4()
        if (protocol == TCP4 && tryV4 == nil) || (protocol == TCP6 && tryV4 != nil) {
            err = UnmatchedIPAddress
        }
    }
    return
}
