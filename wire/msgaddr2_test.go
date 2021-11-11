package wire

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

// hexToBytes converts the passed hex string into bytes and will panic if there
// is an error.  This is only provided for the hard-coded constants so errors in
// the source code can be detected. It will only (and must only) be called with
// hard-coded values.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

// TestAddrV2 tests the MsgAddrV2 API.
func TestAddrV2(t *testing.T) {
	pver := ProtocolVersion

	// Ensure the command is expected value.
	wantCmd := "addrv2"
	msg := NewMsgAddrV2()
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgAddrV2: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for latest protocol version.
	// Num addresses (varInt) + num * (time + services + networkID + addr len + addr + port)
	wantPayload := uint32(9 + 1000*(4+9+1+9+512+2))
	maxPayload := msg.MaxPayloadLength(pver)
	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Ensure NetAddresses are added properly.
	tcpAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	na := NewNetAddressV2(tcpAddr, SFNodeNetwork)
	err := msg.AddAddress(na)
	if err != nil {
		t.Errorf("AddAddress: %v", err)
	}
	if msg.AddrList[0] != na {
		t.Errorf("AddAddress: wrong address added - got %v, want %v",
			spew.Sprint(msg.AddrList[0]), spew.Sprint(na))
	}

	// Ensure the address list is cleared properly.
	msg.ClearAddresses()
	if len(msg.AddrList) != 0 {
		t.Errorf("ClearAddresses: address list is not empty - "+
			"got %v [%v], want %v", len(msg.AddrList),
			spew.Sprint(msg.AddrList[0]), 0)
	}

	// Ensure adding more than the max allowed addresses per message returns
	// error.
	for i := 0; i < MaxAddrPerMsg+1; i++ {
		err = msg.AddAddress(na)
	}
	if err == nil {
		t.Errorf("AddAddress: expected error on too many addresses " +
			"not received")
	}
	err = msg.AddAddresses(na)
	if err == nil {
		t.Errorf("AddAddresses: expected error on too many addresses " +
			"not received")
	}
}

// TestAddrV2Wire tests the MsgAddrV2 wire encode and decode for various numbers
// of addresses and protocol versions.
func TestAddrV2Wire(t *testing.T) {
	// A couple of NetAddresses to use for testing.
	na := &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("127.0.0.1").To4(),
			Port:      8333,
		},
		NetworkID: NIIPV4,
	}
	na2 := &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("192.168.0.1").To4(),
			Port:      8334,
		},
		NetworkID: NIIPV4,
	}

	// Empty address message.
	noAddr := NewMsgAddrV2()
	noAddrEncoded := []byte{
		0x00, // Varint for number of addresses
	}

	// Address message with multiple addresses.
	multiAddr := NewMsgAddrV2()
	multiAddr.AddAddresses(na, na2)
	multiAddrEncoded := []byte{
		0x02,                   // Varint for number of addresses
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01,                   // services (CompactSize)
		0x01,                   // networkID
		0x04,                   // addr size (CompactSize)
		0x7f, 0x00, 0x00, 0x01, // IP 127.0.0.1
		0x20, 0x8d, // Port 8333 in big-endian
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01,                   // services (CompactSize)
		0x01,                   // networkID
		0x04,                   // addr size (CompactSize)
		0xc0, 0xa8, 0x00, 0x01, // IP 192.168.0.1
		0x20, 0x8e, // Port 8334 in big-endian
	}

	tests := []struct {
		in   *MsgAddrV2      // Message to encode
		out  *MsgAddrV2      // Expected decoded message
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version with no addresses.
		{
			noAddr,
			noAddr,
			noAddrEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Latest protocol version with multiple addresses.
		{
			multiAddr,
			multiAddr,
			multiAddrEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion-1 with no addresses.
		{
			noAddr,
			noAddr,
			noAddrEncoded,
			MultipleAddressVersion - 1,
			BaseEncoding,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire format.
		var buf bytes.Buffer
		err := test.in.BtcEncode(&buf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcEncode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BtcEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		var msg MsgAddrV2
		rbuf := bytes.NewReader(test.buf)
		err = msg.BtcDecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcDecode #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("BtcDecode #%d\n got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestAddrV2WireErrors performs negative tests against wire encode and decode
// of MsgAddrV2 to confirm error paths work correctly.
func TestAddrV2WireErrors(t *testing.T) {
	pver := ProtocolVersion
	wireErr := &MessageError{}

	// A couple of NetAddresses to use for testing.
	na := &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("127.0.0.1"),
			Port:      8333,
		},
		NetworkID: NIIPV4,
	}
	na2 := &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("192.168.0.1"),
			Port:      8334,
		},
		NetworkID: NIIPV4,
	}

	// Address message with multiple addresses.
	baseAddr := NewMsgAddrV2()
	baseAddr.AddAddresses(na, na2)
	baseAddrEncoded := []byte{
		0x02,                   // Varint for number of addresses
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01,                   // services (CompactSize)
		0x01,                   // networkID
		0x04,                   // addr size (CompactSize)
		0x7f, 0x00, 0x00, 0x01, // IP 127.0.0.1
		0x20, 0x8d, // Port 8333 in big-endian
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01,                   // services (CompactSize)
		0x01,                   // networkID
		0x04,                   // addr size (CompactSize)
		0xc0, 0xa8, 0x00, 0x01, // IP 192.168.0.1
		0x20, 0x8e, // Port 8334 in big-endian

	}

	// Message that forces an error by having more than the max allowed
	// addresses.
	maxAddr := NewMsgAddrV2()
	for i := 0; i < MaxAddrPerMsg; i++ {
		maxAddr.AddAddress(na)
	}
	maxAddr.AddrList = append(maxAddr.AddrList, na)
	maxAddrEncoded := []byte{
		0xfd, 0x03, 0xe9, // Varint for number of addresses (1001)
	}

	tests := []struct {
		in       *MsgAddrV2      // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force error in addresses count
		{baseAddr, baseAddrEncoded, pver, BaseEncoding, 0, io.ErrShortWrite, io.EOF},
		// Force error in address list.
		{baseAddr, baseAddrEncoded, pver, BaseEncoding, 1, io.ErrShortWrite, io.EOF},
		// Force error with greater than max inventory vectors.
		{maxAddr, maxAddrEncoded, pver, BaseEncoding, 3, wireErr, wireErr},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)
		err := test.in.BtcEncode(w, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.writeErr) {
			t.Errorf("BtcEncode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		if _, ok := err.(*MessageError); !ok {
			if err != test.writeErr {
				t.Errorf("BtcEncode #%d wrong error got: %v, "+
					"want: %v", i, err, test.writeErr)
				continue
			}
		}

		// Decode from wire format.
		var msg MsgAddr
		r := newFixedReader(test.max, test.buf)
		err = msg.BtcDecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.readErr) {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		if _, ok := err.(*MessageError); !ok {
			if err != test.readErr {
				t.Errorf("BtcDecode #%d wrong error got: %v, "+
					"want: %v", i, err, test.readErr)
				continue
			}
		}

	}
}

// TestAddrV2WireHex tests the MsgAddrV2 wire encode and decode for various numbers
// of addresses and protocol versions.
func TestAddrV2WireHex(t *testing.T) {

	// Tests from https://github.com/ZcashFoundation/zebra/blob/afb8b3d4775d89b3f9223447341bf6ce152f5c3a/zebra-test/src/network_addr.rs#L87

	// stream_addrv2_hex
	msgAddrHex0 := hexToBytes(strings.Join([]string{
		"03",                               // number of entries
		"61bc6649",                         // time, Fri Jan  9 02:54:25 UTC 2009
		"00",                               // service flags, COMPACTSIZE(NODE_NONE)
		"02",                               // network id, IPv6
		"10",                               // address length, COMPACTSIZE(16)
		"00000000000000000000000000000001", // address, ::1
		"0000",                             // port, 0

		"79627683",                         // time, Tue Nov 22 11:22:33 UTC 2039
		"01",                               // service flags, COMPACTSIZE(NODE_NETWORK)
		"02",                               // network id, IPv6
		"10",                               // address length, COMPACTSIZE(16)
		"00000000000000000000000000000001", // address, ::1
		"00f1",                             // port, 241

		"79627683", // time, Tue Nov 22 11:22:33 UTC 2039
		"01",       // service flags, COMPACTSIZE(NODE_NETWORK)
		"04",       // network id, TorV3
		"20",       // address length, COMPACTSIZE(32)
		"53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88",
		// address, (32 byte Tor v3 onion service public key)
		"235a", // port, 9050
	}, ""))
	msgAddr0 := NewMsgAddrV2()
	msgAddr0.AddAddresses(&NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x4966bc61, 0),
			Services:  0,
			IP:        net.ParseIP("::1").To16(),
			Port:      0,
		},
		NetworkID: NIIPV6,
	}, &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("::1").To16(),
			Port:      241,
		},
		NetworkID: NIIPV6,
	}, &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			Port:      9050,
		},
		NetworkID: NITorV3,
		Addr:      hexToBytes("53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88"),
	})

	// IPv4
	msgAddrHex1 := hexToBytes(strings.Join([]string{
		"02", // number of entries

		"79627683", // time, Tue Nov 22 11:22:33 UTC 2039
		"01",       // service flags, COMPACTSIZE(NODE_NETWORK)
		"01",       // network id, IPv4
		"04",       // address length, COMPACTSIZE(4)
		"7f000001", // address, 127.0.0.1
		"0001",     // port, 1

		// check that variable-length encoding works
		"79627683",                         // time, Tue Nov 22 11:22:33 UTC 2039
		"01",                               // service flags, COMPACTSIZE(NODE_NETWORK)
		"02",                               // network id, IPv6
		"10",                               // address length, COMPACTSIZE(16)
		"00000000000000000000000000000001", // address, ::1
		"00f1",                             // port, 241
	}, ""))
	msgAddr1 := NewMsgAddrV2()
	msgAddr1.AddAddresses(&NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("127.0.0.1").To4(),
			Port:      1,
		},
		NetworkID: NIIPV4,
	}, &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("::1").To16(),
			Port:      241,
		},
		NetworkID: NIIPV6,
	})

	// all services flags set
	msgAddrHex2 := hexToBytes(strings.Join([]string{
		"01", // number of entries

		"79627683",                         // time, Tue Nov 22 11:22:33 UTC 2039
		"ffffffffffffffffff",               // service flags, COMPACTSIZE(all flags set)
		"02",                               // network id, IPv6
		"10",                               // address length, COMPACTSIZE(16)
		"00000000000000000000000000000001", // address, ::1
		"0000",                             // port, 0
	}, ""))
	msgAddr2 := NewMsgAddrV2()
	msgAddr2.AddAddresses(&NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  0xffffffffffffffff,
			IP:        net.ParseIP("::1").To16(),
			Port:      0,
		},
		NetworkID: NIIPV6,
	})

	// Unknown Network ID: address within typical size range
	msgAddrHex3 := hexToBytes(strings.Join([]string{
		"02", // number of entries

		"79627683",         // time, Tue Nov 22 11:22:33 UTC 2039
		"01",               // service flags, COMPACTSIZE(NODE_NETWORK)
		"fb",               // network id, (unknown)
		"08",               // address length, COMPACTSIZE(8)
		"0000000000000000", // address, (8 zero bytes)
		"0001",             // port, 1

		// check that variable-length encoding works
		"79627683",                         // time, Tue Nov 22 11:22:33 UTC 2039
		"01",                               // service flags, COMPACTSIZE(NODE_NETWORK)
		"02",                               // network id, IPv6
		"10",                               // address length, COMPACTSIZE(16)
		"00000000000000000000000000000001", // address, ::1
		"00f1",                             // port, 241
	}, ""))
	msgAddr3 := NewMsgAddrV2()
	msgAddr3.AddAddresses(&NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			Port:      1,
		},
		Addr:      hexToBytes("0000000000000000"),
		NetworkID: 0xfb,
	}, &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("::1").To16(),
			Port:      241,
		},
		NetworkID: NIIPV6,
	})

	// Unknown Network ID: zero-sized address
	msgAddrHex4 := hexToBytes(strings.Join([]string{
		"02", // number of entries

		"79627683", // time, Tue Nov 22 11:22:33 UTC 2039
		"01",       // service flags, COMPACTSIZE(NODE_NETWORK)
		"fc",       // network id, (unknown)
		"00",       // address length, COMPACTSIZE(0)
		"",         // address, (no bytes)
		"0001",     // port, 1

		// check that variable-length encoding works
		"79627683",                         // time, Tue Nov 22 11:22:33 UTC 2039
		"01",                               // service flags, COMPACTSIZE(NODE_NETWORK)
		"02",                               // network id, IPv6
		"10",                               // address length, COMPACTSIZE(16)
		"00000000000000000000000000000001", // address, ::1
		"00f1",                             // port, 241
	}, ""))
	msgAddr4 := NewMsgAddrV2()
	msgAddr4.AddAddresses(&NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			Port:      1,
		},
		Addr:      []byte{},
		NetworkID: 0xfc,
	}, &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("::1").To16(),
			Port:      241,
		},
		NetworkID: NIIPV6,
	})

	// Unknown Network ID: maximum-sized address
	msgAddrHex5 := hexToBytes(strings.Join([]string{
		"02", // number of entries

		"79627683",                // time, Tue Nov 22 11:22:33 UTC 2039
		"01",                      // service flags, COMPACTSIZE(NODE_NETWORK)
		"fd",                      // network id, (unknown)
		"fd0002",                  // address length, COMPACTSIZE(512)
		strings.Repeat("00", 512), // address, (512 zero bytes)
		"0001",                    // port, 1

		// check that variable-length encoding works
		"79627683",                         // time, Tue Nov 22 11:22:33 UTC 2039
		"01",                               // service flags, COMPACTSIZE(NODE_NETWORK)
		"02",                               // network id, IPv6
		"10",                               // address length, COMPACTSIZE(16)
		"00000000000000000000000000000001", // address, ::1
		"00f1",                             // port, 241
	}, ""))
	msgAddr5 := NewMsgAddrV2()
	msgAddr5.AddAddresses(&NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			Port:      1,
		},
		Addr:      bytes.Repeat([]byte{0x00}, 512),
		NetworkID: 0xfd,
	}, &NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x83766279, 0),
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("::1").To16(),
			Port:      241,
		},
		NetworkID: NIIPV6,
	})

	// Empty list
	msgAddrHex6 := hexToBytes(strings.Join([]string{
		"00", // number of entries
	}, ""))
	msgAddr6 := NewMsgAddrV2()

	tests := []struct {
		in   *MsgAddrV2      // Message to encode
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		{msgAddr0, msgAddrHex0, ProtocolVersion, BaseEncoding},
		{msgAddr1, msgAddrHex1, ProtocolVersion, BaseEncoding},
		{msgAddr2, msgAddrHex2, ProtocolVersion, BaseEncoding},
		{msgAddr3, msgAddrHex3, ProtocolVersion, BaseEncoding},
		{msgAddr4, msgAddrHex4, ProtocolVersion, BaseEncoding},
		{msgAddr5, msgAddrHex5, ProtocolVersion, BaseEncoding},
		{msgAddr6, msgAddrHex6, ProtocolVersion, BaseEncoding},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire format.
		var buf bytes.Buffer
		err := test.in.BtcEncode(&buf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcEncode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BtcEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		var msg MsgAddrV2
		rbuf := bytes.NewReader(test.buf)
		err = msg.BtcDecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcDecode #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&msg, test.in) {
			t.Errorf("BtcDecode #%d\n got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(test.in))
			continue
		}
	}
}

// TestAddrV2WireHexErrors performs negative tests against wire encode and decode
// of MsgAddrV2 to confirm error paths work correctly.
func TestAddrV2WireHexErrors(t *testing.T) {

	// Tests from https://github.com/ZcashFoundation/zebra/blob/afb8b3d4775d89b3f9223447341bf6ce152f5c3a/zebra-test/src/network_addr.rs#L87

	wireErr := &MessageError{}

	// Invalid address size: too large, but under CompactSizeMessage limit
	msgAddrHex0 := hexToBytes(strings.Join([]string{
		"02", // number of entries

		"79627683",                // time, Tue Nov 22 11:22:33 UTC 2039
		"01",                      // service flags, COMPACTSIZE(NODE_NETWORK)
		"fe",                      // network id, (unknown)
		"fd0102",                  // invalid address length, COMPACTSIZE(513)
		strings.Repeat("00", 513), // address, (513 zero bytes)
		"0001",                    // port, 1

		// check that the entire message is ignored
		"79627683",                         // time, Tue Nov 22 11:22:33 UTC 2039
		"01",                               // service flags, COMPACTSIZE(NODE_NETWORK)
		"02",                               // network id, IPv6
		"10",                               // address length, COMPACTSIZE(16)
		"00000000000000000000000000000001", // address, ::1
		"00f1",                             // port, 241
	}, ""))

	// Invalid address size: too large, over CompactSizeMessage limit
	msgAddrHex1 := hexToBytes(strings.Join([]string{
		"01", // number of entries

		"79627683",   // time, Tue Nov 22 11:22:33 UTC 2039
		"01",         // service flags, COMPACTSIZE(NODE_NETWORK)
		"ff",         // network id, (unknown)
		"feffffff7f", // invalid address length, COMPACTSIZE(2^31 - 1)
		// no address, generated bytes wouldn't fit in memory
	}, ""))

	tests := []struct {
		buf     []byte          // Wire encoding
		pver    uint32          // Protocol version for wire encoding
		enc     MessageEncoding // Message encoding format
		readErr error           // Expected read error
	}{
		{msgAddrHex0, ProtocolVersion, BaseEncoding, wireErr},
		{msgAddrHex1, ProtocolVersion, BaseEncoding, wireErr},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Decode the message from wire format.
		var msg MsgAddrV2
		rbuf := bytes.NewReader(test.buf)
		err := msg.BtcDecode(rbuf, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.readErr) {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}
