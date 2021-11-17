package wire

import (
	"fmt"
	"io"
)

type MsgAddrV2 struct {
	AddrList []*NetAddressV2
}

// AddAddress adds a known active peer to the message.
func (msg *MsgAddrV2) AddAddress(na *NetAddressV2) error {
	if len(msg.AddrList)+1 > MaxAddrPerMsg {
		str := fmt.Sprintf("too many addresses in message [max %v]",
			MaxAddrPerMsg)
		return messageError("MsgAddrV2.AddAddress", str)
	}

	msg.AddrList = append(msg.AddrList, na)
	return nil
}

// AddAddresses adds multiple known active peers to the message.
func (msg *MsgAddrV2) AddAddresses(netAddrs ...*NetAddressV2) error {
	for _, na := range netAddrs {
		err := msg.AddAddress(na)
		if err != nil {
			return err
		}
	}
	return nil
}

// ClearAddresses removes all addresses from the message.
func (msg *MsgAddrV2) ClearAddresses() {
	msg.AddrList = []*NetAddressV2{}
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgAddrV2) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Limit to max addresses per message.
	if count > MaxAddrPerMsg {
		str := fmt.Sprintf("too many addresses for message "+
			"[count %v, max %v]", count, MaxAddrPerMsg)
		return messageError("MsgAddrV2.BtcDecode", str)
	}

	addrList := make([]NetAddressV2, count)
	msg.AddrList = make([]*NetAddressV2, 0, count)
	for i := uint64(0); i < count; i++ {
		na := &addrList[i]
		err := readNetAddressV2(r, pver, na)
		if err != nil {
			return err
		}
		msg.AddAddress(na)
	}
	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgAddrV2) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	count := len(msg.AddrList)
	if count > MaxAddrPerMsg {
		str := fmt.Sprintf("too many addresses for message "+
			"[count %v, max %v]", count, MaxAddrPerMsg)
		return messageError("MsgAddrV2.BtcEncode", str)
	}

	err := WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, na := range msg.AddrList {
		err = writeNetAddressV2(w, pver, na)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgAddrV2) Command() string {
	return CmdAddrV2
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgAddrV2) MaxPayloadLength(pver uint32) uint32 {
	// Num addresses (varInt) + max allowed addresses.
	return MaxVarIntPayload + (MaxAddrPerMsg * maxNetAddressPayloadV2(pver))
}

// NewMsgAddrV2 returns a new bitcoin addrv2 message that conforms to the
// Message interface.
func NewMsgAddrV2() *MsgAddrV2 {
	return &MsgAddrV2{
		AddrList: make([]*NetAddressV2, 0, MaxAddrPerMsg),
	}
}
