package wire

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

// TestNetAddressV2 tests the NetAddress API.
func TestNetAddressV2(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	port := 8333

	// Test NewNetAddressV2.
	na := NewNetAddressV2(&net.TCPAddr{IP: ip, Port: port}, 0)

	// Ensure we get the same ip, port, and services back out.
	if !na.IP.Equal(ip) {
		t.Errorf("NetNetAddressV2: wrong ip - got %v, want %v", na.IP, ip)
	}
	if na.Port != uint16(port) {
		t.Errorf("NetNetAddressV2: wrong port - got %v, want %v", na.Port,
			port)
	}
	if na.Services != 0 {
		t.Errorf("NetNetAddressV2: wrong services - got %v, want %v",
			na.Services, 0)
	}
	if na.NetworkID != NIIPV4 {
		t.Errorf("NetNetAddressV2: wrong NetworkID - got %v, want %v",
			na.NetworkID, NIIPV4)
	}
	if na.HasService(SFNodeNetwork) {
		t.Errorf("HasService: SFNodeNetwork service is set")
	}

	// Ensure adding the full service node flag works.
	na.AddService(SFNodeNetwork)
	if na.Services != SFNodeNetwork {
		t.Errorf("AddService: wrong services - got %v, want %v",
			na.Services, SFNodeNetwork)
	}
	if !na.HasService(SFNodeNetwork) {
		t.Errorf("HasService: SFNodeNetwork service not set")
	}

	// Ensure max payload is expected value for latest protocol version.
	pver := ProtocolVersion
	wantPayload := uint32(512 + 25)
	maxPayload := maxNetAddressPayloadV2(ProtocolVersion)
	if maxPayload != wantPayload {
		t.Errorf("maxNetAddressPayloadV2: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}
}

// TestNetAddressWireV2 tests the NetAddress wire encode and decode for various
// protocol versions and timestamp flag combinations.
func TestNetAddressWireV2(t *testing.T) {
	// baseNetAddr is used in the various tests as a baseline NetAddress.
	baseNetAddr := NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("127.0.0.1").To4(),
			Port:      8333,
		},
		NetworkID: NIIPV4,
	}

	// baseNetAddrNoTS is baseNetAddr with a zero value for the timestamp.
	baseNetAddrNoTS := baseNetAddr
	baseNetAddrNoTS.Timestamp = time.Time{}

	// baseNetAddrEncoded is the wire encoded bytes of baseNetAddr.
	baseNetAddrEncoded := []byte{
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01,                   // SFNodeNetwork
		0x01,                   // IPV4
		0x04,                   // addr size
		0x7f, 0x00, 0x00, 0x01, // IP 127.0.0.1
		0x20, 0x8d, // Port 8333 in big-endian
	}

	tests := []struct {
		in   NetAddressV2 // NetAddress to encode
		out  NetAddressV2 // Expected decoded NetAddress
		buf  []byte       // Wire encoding
		pver uint32       // Protocol version for wire encoding
	}{
		// Latest protocol version with ts flag.
		{
			baseNetAddr,
			baseNetAddr,
			baseNetAddrEncoded,
			ProtocolVersion,
		},

		// Protocol version NetAddressTimeVersion with ts flag.
		{
			baseNetAddr,
			baseNetAddr,
			baseNetAddrEncoded,
			NetAddressTimeVersion,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire format.
		var buf bytes.Buffer
		err := writeNetAddressV2(&buf, test.pver, &test.in)
		if err != nil {
			t.Errorf("writeNetAddressV2 #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("writeNetAddressV2 #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		var na NetAddressV2
		rbuf := bytes.NewReader(test.buf)
		err = readNetAddressV2(rbuf, test.pver, &na)
		if err != nil {
			t.Errorf("readNetAddressV2 #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(na, test.out) {
			t.Errorf("readNetAddressV2 #%d\n got: %s want: %s", i,
				spew.Sdump(na), spew.Sdump(test.out))
			continue
		}
	}
}

// TestNetAddressV2WireErrors performs negative tests against wire encode and
// decode NetAddress to confirm error paths work correctly.
func TestNetAddressV2WireErrors(t *testing.T) {
	pver := ProtocolVersion

	// baseNetAddr is used in the various tests as a baseline NetAddress.
	baseNetAddr := NetAddressV2{
		NetAddress: NetAddress{
			Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
			Services:  SFNodeNetwork,
			IP:        net.ParseIP("127.0.0.1"),
			Port:      8333,
		},
		NetworkID: NIIPV4,
	}

	tests := []struct {
		in       *NetAddressV2 // Value to encode
		buf      []byte        // Wire encoding
		pver     uint32        // Protocol version for wire encoding
		max      int           // Max size of fixed buffer to induce errors
		writeErr error         // Expected write error
		readErr  error         // Expected read error
	}{
		// Latest protocol version with timestamp and intentional
		// read/write errors.
		// Force errors on timestamp.
		{&baseNetAddr, []byte{}, pver, 0, io.ErrShortWrite, io.EOF},
		// Force errors on services.
		{&baseNetAddr, []byte{}, pver, 4, io.ErrShortWrite, io.EOF},
		// Force errors on networkID.
		{&baseNetAddr, []byte{}, pver, 5, io.ErrShortWrite, io.EOF},
		// Force errors on address.
		{&baseNetAddr, []byte{}, pver, 6, io.ErrShortWrite, io.EOF},
		// Force errors on port.
		{&baseNetAddr, []byte{}, pver, 11, io.ErrShortWrite, io.EOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)
		err := writeNetAddressV2(w, test.pver, test.in)
		if err != test.writeErr {
			t.Errorf("writeNetAddressV2 #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		buf := new(bytes.Buffer)
		err = writeNetAddressV2(buf, test.pver, test.in)
		if err != nil {
			t.Errorf("writeNetAddressV2 failed: %v", err)
			continue
		}

		// Decode from wire format.
		var na NetAddressV2
		r := newFixedReader(test.max, buf.Bytes())
		err = readNetAddressV2(r, test.pver, &na)
		if err != test.readErr {
			t.Errorf("readNetAddressV2 #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}
