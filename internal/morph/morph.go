package morph

import (
	"math"
	"math/rand/v2"
	"time"
)

// Morpher implements continuous exponential decay morphing.
// Instead of a binary phase switch (detectable), padding probability
// decays smoothly from 1.0 at t=0 to ~0 at t=30s.
type Morpher struct {
	tau float64 // decay time constant in seconds (default 10.0)
}

func New(tau float64) *Morpher {
	if tau <= 0 {
		tau = 10.0
	}
	return &Morpher{tau: tau}
}

// PaddingProbability returns the probability of adding padding at a given stream age.
// At t=0: 1.0 (always pad)
// At t=tau: 0.37 (37%)
// At t=3*tau: 0.05 (5%)
func (m *Morpher) PaddingProbability(streamAge time.Duration) float64 {
	return math.Exp(-streamAge.Seconds() / m.tau)
}

// ShouldPad returns true if padding should be added at the current stream age.
func (m *Morpher) ShouldPad(streamAge time.Duration) bool {
	return rand.Float64() < m.PaddingProbability(streamAge)
}

// PadSize returns a random padding size sampled from empirical Chrome HTTP/2
// frame size distribution. This avoids uniform sizes (which are themselves a fingerprint).
func (m *Morpher) PadSize() int {
	return SampleFrameSize()
}

// Chrome HTTP/2 frame size distribution (empirically measured)
var frameSizeDist = []weightedSize{
	{size: 45, weight: 0.15},    // HEADERS frames
	{size: 100, weight: 0.10},   // Small DATA frames
	{size: 500, weight: 0.20},   // Medium DATA frames
	{size: 1400, weight: 0.25},  // Near-MTU DATA frames
	{size: 16384, weight: 0.30}, // Max HTTP/2 frame (bulk)
}

type weightedSize struct {
	size   int
	weight float64
}

// SampleFrameSize returns a frame size from the empirical distribution.
func SampleFrameSize() int {
	r := rand.Float64()
	cumulative := 0.0
	for _, ws := range frameSizeDist {
		cumulative += ws.weight
		if r <= cumulative {
			// Add some jitter ±20%
			jitter := 1.0 + (rand.Float64()-0.5)*0.4
			size := int(float64(ws.size) * jitter)
			if size < 1 {
				size = 1
			}
			return size
		}
	}
	return frameSizeDist[len(frameSizeDist)-1].size
}

// InterPacketDelay returns a random delay sampled from a realistic distribution.
// During early stream lifetime (high stealth): 5-20ms
// During later lifetime (low stealth): 0-2ms
func (m *Morpher) InterPacketDelay(streamAge time.Duration) time.Duration {
	p := m.PaddingProbability(streamAge)
	if p < 0.05 {
		return 0 // No delay in bulk phase
	}
	// Scale delay with padding probability
	maxDelay := 20.0 * p // ms
	delay := rand.Float64() * maxDelay
	return time.Duration(delay * float64(time.Millisecond))
}
