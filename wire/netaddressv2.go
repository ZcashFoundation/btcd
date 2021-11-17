package wire

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// MaxAddrV2Size is the maximum size of an addresses in a bitcoin addrv2 message
// (MsgAddrV2).
const MaxAddrV2Size = 512

// NetworkID specifies which network is addressed by the NetAddressV2 struct.
type NetworkID byte

const (
	// NIIPV4 is a IPv4 address (globally routed internet)
	NIIPV4 NetworkID = 0x01
	// NIIPV6 is a IPv6 address (globally routed internet)
	NIIPV6 NetworkID = 0x02
	// NITorV2 is a Tor v2 hidden service address.
	// Disabled by Tor as of October 2021:
	// https://support.torproject.org/onionservices/v2-deprecation/
	NITorV2 NetworkID = 0x03
	// NITorV3 is a Tor v3 hidden service address
	NITorV3 NetworkID = 0x04
	// NII2P is a NII2P overlay network address
	NII2P NetworkID = 0x05
	// NICjdns is a Cjdns overlay network address
	NICjdns NetworkID = 0x06
)

var AddressSizeByNetworkID = map[NetworkID]uint64{
	NIIPV4:  4,
	NIIPV6:  16,
	NITorV2: 10,
	NITorV3: 32,
	NII2P:   32,
	NICjdns: 16,
}

// maxNetAddressPayloadV2 returns the max payload size for a bitcoin NetAddressV2
// based on the protocol version.
func maxNetAddressPayloadV2(pver uint32) uint32 {
	// Timestamp 4 bytes
	plen := uint32(4)
	// services
	plen += MaxVarIntPayload
	// networkID
	plen += 1
	// address
	// We use 3 instead of MaxVarIntPayload because of MaxAddrV2Size limit,
	// which forces the CompactSize prefix to have at most 3 bytes
	// (1 byte length selection prefix, plus a 2 byte integer).
	plen += 3 + MaxAddrV2Size
	// port
	plen += 2
	return plen
}

// Return the NetworkID of the given IP address and its canonical form
// (4-byte if IPV4, 16-byte if IPV6).
func getNetworkID(ip net.IP) (net.IP, NetworkID) {
	if ip.To4() != nil {
		return ip.To4(), NIIPV4
	} else {
		return ip.To16(), NIIPV6
	}
}

// NetAddressV2 defines information about a peer on the network including the time
// it was last seen, the services it supports, its IP address, and port.
type NetAddressV2 struct {
	// NetAddress is the embedded version1 address.
	NetAddress

	// NetworkID specifies which network is addressed.
	NetworkID NetworkID

	// Addr is the raw address of the peer, if NetworkID is not IPV4 nor IPV6.
	Addr []byte
}

// NewNetAddressV2IPPort returns a new NetAddressV2 using the provided IP, port, and
// supported services with defaults for the remaining fields.
func NewNetAddressV2IPPort(ip net.IP, port uint16, services ServiceFlag) *NetAddressV2 {
	return NewNetAddressV2Timestamp(time.Now(), services, ip, port)
}

// NewNetAddressV2Timestamp returns a new NetAddressV2 using the provided
// timestamp, IP, port, and supported services. The timestamp is rounded to
// single second precision.
func NewNetAddressV2Timestamp(
	timestamp time.Time, services ServiceFlag, ip net.IP, port uint16) *NetAddressV2 {

	ip, networkID := getNetworkID(ip)
	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	na := NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(timestamp.Unix(), 0),
			Services:  services,
			IP:        ip,
			Port:      port,
		},
		NetworkID: networkID,
	}
	return &na
}

// NewNetAddressV2 returns a new NetAddressV2 using the provided TCP address and
// supported services with defaults for the remaining fields.
func NewNetAddressV2(addr *net.TCPAddr, services ServiceFlag) *NetAddressV2 {
	return NewNetAddressV2IPPort(addr.IP, uint16(addr.Port), services)
}

// NewNetAddressV2NetAddress returns a new NetAddressV2 from the provided NetAddress.
func NewNetAddressV2NetAddress(addr1 *NetAddress) *NetAddressV2 {
	return NewNetAddressV2Timestamp(addr1.Timestamp, addr1.Services, addr1.IP, addr1.Port)
}

// readNetAddressV2 reads an encoded NetAddressV2 from r depending on the protocol
// version.
func readNetAddressV2(r io.Reader, pver uint32, na *NetAddressV2) error {
	var networkID NetworkID

	// NOTE: The bitcoin protocol uses a uint32 for the timestamp so it will
	// stop working somewhere around 2106.
	err := readElement(r, (*uint32Time)(&na.Timestamp))
	if err != nil {
		return err
	}

	services, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	na.Services = ServiceFlag(services)

	err = readElements(r, &networkID)
	if err != nil {
		return err
	}

	sizeAddr, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if sizeAddr > MaxAddrV2Size {
		str := fmt.Sprintf("addr in addrv2 message is too big "+
			"[count %v, max %v]", sizeAddr, MaxAddrV2Size)
		return messageError("readNetAddressV2", str)
	}
	correctSize, ok := AddressSizeByNetworkID[networkID]
	// Unknown network IDs are allowed to be parsed.
	if ok && sizeAddr != correctSize {
		str := fmt.Sprintf("incorrect addr size in addrv2 message "+
			"[size %v, expected %v]", sizeAddr, correctSize)
		return messageError("readNetAddressV2", str)
	}

	var addr []byte = make([]byte, sizeAddr)
	_, err = io.ReadFull(r, addr)
	if err != nil {
		return err
	}

	port, err := binarySerializer.Uint16(r, bigEndian)
	if err != nil {
		return err
	}

	*na = NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: na.Timestamp,
			Services:  na.Services,
			Port:      port,
		},
		NetworkID: networkID,
	}

	switch networkID {
	case NIIPV4:
		na.IP = net.IP(addr).To4()
	case NIIPV6:
		na.IP = net.IP(addr).To16()
	default:
		na.Addr = addr
	}

	return nil
}

// writeNetAddressV2 serializes a NetAddressV2 to w depending on the protocol
// version.
func writeNetAddressV2(w io.Writer, pver uint32, na *NetAddressV2) error {
	// NOTE: The bitcoin protocol uses a uint32 for the timestamp so it will
	// stop working somewhere around 2106.
	err := writeElement(w, uint32(na.Timestamp.Unix()))
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(na.Services))
	if err != nil {
		return err
	}

	var addr []byte
	var networkID NetworkID
	if len(na.IP) > 0 {
		addr, networkID = getNetworkID(na.IP)
	} else {
		addr = na.Addr
		networkID = na.NetworkID
	}

	err = writeElements(w, networkID)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(addr)))
	if err != nil {
		return err
	}

	err = writeElements(w, addr)
	if err != nil {
		return err
	}

	return binary.Write(w, bigEndian, na.Port)
}
