// Package mux implements munnel's stream multiplexer: many logical
// full-duplex streams carried over a single persistent TCP connection.
//
// Wire format — a fixed 9-byte binary header followed by the payload:
//
//	+--------+-----------+---------+
//	| type   | stream id | length  |
//	| 1 byte | 4 bytes   | 4 bytes |
//	+--------+-----------+---------+
//
// All integers are big-endian. The payload length may be zero.
package mux

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// HeaderSize is the size of the fixed binary frame header.
	HeaderSize = 9

	// MaxPayload is the largest payload carried in a single frame.
	// Writers chunk larger writes into multiple frames automatically.
	MaxPayload = 1 << 20 // 1 MiB
)

// Frame types.
const (
	// FrameOpen opens a new stream. Payload is an optional JSON metadata blob.
	FrameOpen byte = 0x01
	// FrameData carries stream payload bytes.
	FrameData byte = 0x02
	// FramePing is a keepalive probe. Payload is an 8-byte unix-nano timestamp.
	FramePing byte = 0x03
	// FramePong replies to a ping, echoing the timestamp.
	FramePong byte = 0x04
	// FrameClose means the sender has finished writing (the receiver will see
	// EOF once buffered data is drained). A stream is fully closed once both
	// sides have sent FrameClose.
	FrameClose byte = 0x05
	// FrameReset aborts the stream immediately in both directions.
	FrameReset byte = 0x06
)

var frameTypeName = map[byte]string{
	FrameOpen:  "OPEN",
	FrameData:  "DATA",
	FramePing:  "PING",
	FramePong:  "PONG",
	FrameClose: "CLOSE",
	FrameReset: "RESET",
}

func frameName(t byte) string {
	if n, ok := frameTypeName[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%02x", t)
}

// writeFrame serializes one frame onto w. Callers must hold write
// serialization themselves (Session does this internally).
func writeFrame(w io.Writer, typ byte, streamID uint32, payload []byte) error {
	var hdr [HeaderSize]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], streamID)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readFrame reads exactly one frame from r. The returned payload slice is
// owned by the caller. A nil payload is returned for zero-length frames.
func readFrame(r io.Reader) (typ byte, streamID uint32, payload []byte, err error) {
	var hdr [HeaderSize]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	typ = hdr[0]
	streamID = binary.BigEndian.Uint32(hdr[1:5])
	n := binary.BigEndian.Uint32(hdr[5:9])
	if n > MaxPayload {
		return 0, 0, nil, fmt.Errorf("mux: frame payload %d exceeds max %d", n, MaxPayload)
	}
	if n == 0 {
		return typ, streamID, nil, nil
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	return typ, streamID, payload, nil
}
