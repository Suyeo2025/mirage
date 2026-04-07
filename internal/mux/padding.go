package mux

import (
	"encoding/binary"
	"errors"
	"math"
)

// PaddingConfig is a server-configurable padding scheme pushed to clients via CmdSettings.
// Inspired by AnyTLS's hot-updatable padding approach.
type PaddingConfig struct {
	Version uint8 // schema version (currently 1)

	// Exponential decay
	Tau float64 // decay time constant in seconds (default 10.0)

	// First N packets get heavy padding (to mask inner TLS ClientHello)
	EarlyPktCount int    // number of early packets to pad aggressively
	EarlyPadMin   uint16 // min padding bytes for early packets
	EarlyPadMax   uint16 // max padding bytes for early packets

	// Steady-state padding
	SteadyPadMin uint16 // min padding bytes after early phase
	SteadyPadMax uint16 // max padding bytes after early phase

	// Frame size distribution (up to 8 entries)
	FrameSizes []WeightedSize

	// Keepalive
	KeepaliveMin    uint16  // min keepalive padding bytes
	KeepaliveMax    uint16  // max keepalive padding bytes
	KeepaliveMinSec float32 // min interval seconds
	KeepaliveMaxSec float32 // max interval seconds
}

// WeightedSize is a frame size with a probability weight.
type WeightedSize struct {
	Size   uint16
	Weight float32
}

// DefaultPaddingConfig returns sensible defaults matching Chrome HTTP/2 patterns.
func DefaultPaddingConfig() *PaddingConfig {
	return &PaddingConfig{
		Version:       1,
		Tau:           10.0,
		EarlyPktCount: 8,
		EarlyPadMin:   200,
		EarlyPadMax:   1000,
		SteadyPadMin:  0,
		SteadyPadMax:  128,
		FrameSizes: []WeightedSize{
			{Size: 45, Weight: 0.15},    // HEADERS frames
			{Size: 100, Weight: 0.10},   // Small DATA
			{Size: 500, Weight: 0.20},   // Medium DATA
			{Size: 1400, Weight: 0.25},  // Near-MTU DATA
			{Size: 16384, Weight: 0.30}, // Max HTTP/2 frame (bulk)
		},
		KeepaliveMin:    64,
		KeepaliveMax:    512,
		KeepaliveMinSec: 3.0,
		KeepaliveMaxSec: 8.0,
	}
}

// EncodePaddingConfig serializes a PaddingConfig to compact binary.
// Format: [version:1][tau:8][earlyCount:2][earlyMin:2][earlyMax:2]
//
//	[steadyMin:2][steadyMax:2][kaMin:2][kaMax:2][kaMinSec:4][kaMaxSec:4]
//	[numSizes:1][{size:2,weight:4}...]
//
// Total fixed part: 32 bytes + 6 * numSizes
func EncodePaddingConfig(c *PaddingConfig) []byte {
	numSizes := len(c.FrameSizes)
	if numSizes > 255 {
		numSizes = 255
	}
	buf := make([]byte, 32+6*numSizes)
	buf[0] = c.Version
	binary.BigEndian.PutUint64(buf[1:9], math.Float64bits(c.Tau))
	binary.BigEndian.PutUint16(buf[9:11], uint16(c.EarlyPktCount))
	binary.BigEndian.PutUint16(buf[11:13], c.EarlyPadMin)
	binary.BigEndian.PutUint16(buf[13:15], c.EarlyPadMax)
	binary.BigEndian.PutUint16(buf[15:17], c.SteadyPadMin)
	binary.BigEndian.PutUint16(buf[17:19], c.SteadyPadMax)
	binary.BigEndian.PutUint16(buf[19:21], c.KeepaliveMin)
	binary.BigEndian.PutUint16(buf[21:23], c.KeepaliveMax)
	binary.BigEndian.PutUint32(buf[23:27], math.Float32bits(c.KeepaliveMinSec))
	binary.BigEndian.PutUint32(buf[27:31], math.Float32bits(c.KeepaliveMaxSec))
	buf[31] = byte(numSizes)
	off := 32
	for i := 0; i < numSizes; i++ {
		binary.BigEndian.PutUint16(buf[off:off+2], c.FrameSizes[i].Size)
		binary.BigEndian.PutUint32(buf[off+2:off+6], math.Float32bits(c.FrameSizes[i].Weight))
		off += 6
	}
	return buf
}

// DecodePaddingConfig deserializes a PaddingConfig from binary.
func DecodePaddingConfig(data []byte) (*PaddingConfig, error) {
	if len(data) < 32 {
		return nil, errors.New("padding config too short")
	}
	c := &PaddingConfig{
		Version:         data[0],
		Tau:             math.Float64frombits(binary.BigEndian.Uint64(data[1:9])),
		EarlyPktCount:   int(binary.BigEndian.Uint16(data[9:11])),
		EarlyPadMin:     binary.BigEndian.Uint16(data[11:13]),
		EarlyPadMax:     binary.BigEndian.Uint16(data[13:15]),
		SteadyPadMin:    binary.BigEndian.Uint16(data[15:17]),
		SteadyPadMax:    binary.BigEndian.Uint16(data[17:19]),
		KeepaliveMin:    binary.BigEndian.Uint16(data[19:21]),
		KeepaliveMax:    binary.BigEndian.Uint16(data[21:23]),
		KeepaliveMinSec: math.Float32frombits(binary.BigEndian.Uint32(data[23:27])),
		KeepaliveMaxSec: math.Float32frombits(binary.BigEndian.Uint32(data[27:31])),
	}
	numSizes := int(data[31])
	if len(data) < 32+6*numSizes {
		return nil, errors.New("padding config truncated")
	}
	c.FrameSizes = make([]WeightedSize, numSizes)
	off := 32
	for i := 0; i < numSizes; i++ {
		c.FrameSizes[i].Size = binary.BigEndian.Uint16(data[off : off+2])
		c.FrameSizes[i].Weight = math.Float32frombits(binary.BigEndian.Uint32(data[off+2 : off+6]))
		off += 6
	}
	return c, nil
}
