// Package morph implements traffic morphing with Gaussian padding (CCS 2021)
// and configurable server-pushed padding schemes. Implements mux.PaddingOracle.
//
// Key insight from Degabriele (CCS 2021): Gaussian padding achieves sqrt(q)
// multi-sample distinguishability scaling vs linear for uniform padding.
// At 200 bytes mean overhead: Gaussian requires 7,680,000 samples to detect
// vs 76,883 for uniform — a 100x improvement.
package morph

import (
	"math"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

// Config holds morphing parameters. Can be hot-updated via atomic pointer.
type Config struct {
	Tau           float64 // decay time constant (seconds)
	EarlyPktCount int     // first N packets get heavy padding
	EarlyPadMu   int     // Gaussian mean for early packets
	EarlyPadSigma int    // Gaussian sigma for early packets
	SteadyPadMu  int     // Gaussian mean for steady state
	SteadyPadSigma int   // Gaussian sigma for steady state
	FrameSizes   []WeightedSize // frame size distribution for morphing matrix
}

// WeightedSize is a frame size with a probability weight.
type WeightedSize struct {
	Size   int
	Weight float64
}

// DefaultConfig returns defaults with Gaussian parameters tuned for
// Chrome HTTP/2 traffic patterns through Cloudflare.
func DefaultConfig() *Config {
	return &Config{
		Tau:            10.0,
		EarlyPktCount:  8,
		EarlyPadMu:     600, // mean ~600 bytes (masks TLS ClientHello ~517 bytes)
		EarlyPadSigma:  200, // sigma 200 → wide spread, hard to fingerprint
		SteadyPadMu:    50,  // mean ~50 bytes steady-state
		SteadyPadSigma: 15,  // sigma 15 → per Degabriele's recommendation
		FrameSizes: []WeightedSize{
			{Size: 45, Weight: 0.15},
			{Size: 100, Weight: 0.10},
			{Size: 500, Weight: 0.20},
			{Size: 1400, Weight: 0.25},
			{Size: 16384, Weight: 0.30},
		},
	}
}

// Morpher implements mux.PaddingOracle with Gaussian padding and
// exponential decay morphing.
type Morpher struct {
	config atomic.Pointer[Config]
}

// New creates a Morpher with the given config. Pass nil for defaults.
func New(cfg *Config) *Morpher {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Tau <= 0 {
		cfg.Tau = 10.0
	}
	m := &Morpher{}
	m.config.Store(cfg)
	return m
}

// UpdateConfig hot-updates the morphing parameters (thread-safe).
func (m *Morpher) UpdateConfig(cfg *Config) {
	if cfg != nil {
		m.config.Store(cfg)
	}
}

// ShouldPad implements mux.PaddingOracle.
// Uses truncated Gaussian sampling per Degabriele (CCS 2021).
func (m *Morpher) ShouldPad(streamAge time.Duration, pktIndex int64) (bool, int) {
	cfg := m.config.Load()

	// Early packets: always pad with Gaussian distribution
	// This masks the inner TLS ClientHello size/timing signature
	if int(pktIndex) <= cfg.EarlyPktCount {
		size := sampleTruncatedGaussian(cfg.EarlyPadMu, cfg.EarlyPadSigma)
		return true, size
	}

	// Steady state: exponential decay probability
	p := math.Exp(-streamAge.Seconds() / cfg.Tau)
	if rand.Float64() >= p {
		return false, 0
	}

	// Gaussian padding for steady state
	size := sampleTruncatedGaussian(cfg.SteadyPadMu, cfg.SteadyPadSigma)
	return true, size
}

// sampleTruncatedGaussian samples from a truncated rounded Gaussian N_bar(mu, sigma).
// Per Degabriele (CCS 2021), Algorithm 1: Box-Muller → round → clamp to [1, 65535].
// The truncated Gaussian has cover difference CD ≈ 0, meaning multi-sample
// statistical distance grows as O(sqrt(q)) instead of O(q) for uniform.
func sampleTruncatedGaussian(mu, sigma int) int {
	if sigma <= 0 {
		if mu <= 0 {
			return 1
		}
		return mu
	}

	// Box-Muller transform
	u1 := rand.Float64()
	u2 := rand.Float64()
	// Avoid log(0)
	for u1 == 0 {
		u1 = rand.Float64()
	}
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)

	// Round to nearest integer (Degabriele's "rounded Gaussian")
	sample := int(math.Round(z*float64(sigma))) + mu

	// Truncate: clamp to [1, 65535]
	if sample < 1 {
		sample = 1
	}
	if sample > 65535 {
		sample = 65535
	}
	return sample
}

// SplitPlan implements mux.PaddingOracle.
// For early packets (where inner TLS ClientHello is likely to appear),
// returns a plan to split the data into multiple chunks.
// This is equivalent to AnyTLS's "336-696,c,387-791,c,..." syntax
// but with Gaussian-distributed chunk sizes.
func (m *Morpher) SplitPlan(pktIndex int64, dataLen int) []int {
	cfg := m.config.Load()

	// Only split early packets (where TLS handshakes appear)
	if int(pktIndex) > cfg.EarlyPktCount || dataLen < 200 {
		return nil // no split for steady-state or tiny packets
	}

	// Split into 2-5 chunks with Gaussian-distributed sizes.
	// Target: break the characteristic TLS ClientHello (~517 bytes)
	// and ServerHello+Cert (~2-5KB) into unrecognizable fragments.
	numChunks := 2 + int(rand.IntN(3)) // 2-4 chunks
	if dataLen < 400 {
		numChunks = 2 // small data: just split in half
	}

	plan := make([]int, numChunks)
	remaining := dataLen
	for i := 0; i < numChunks-1; i++ {
		// Each chunk: Gaussian around (remaining / chunks_left)
		avg := remaining / (numChunks - i)
		sigma := avg / 4
		if sigma < 10 {
			sigma = 10
		}
		size := sampleTruncatedGaussian(avg, sigma)
		if size > remaining-1 {
			size = remaining - 1 // leave at least 1 byte for next chunk
		}
		if size < 1 {
			size = 1
		}
		plan[i] = size
		remaining -= size
	}
	plan[numChunks-1] = remaining // last chunk gets the rest

	return plan
}

// PaddingProbability returns the decay probability at a given stream age.
func (m *Morpher) PaddingProbability(streamAge time.Duration) float64 {
	cfg := m.config.Load()
	return math.Exp(-streamAge.Seconds() / cfg.Tau)
}

// InterPacketDelay returns a random delay to inject between packets.
func (m *Morpher) InterPacketDelay(streamAge time.Duration) time.Duration {
	p := m.PaddingProbability(streamAge)
	if p < 0.05 {
		return 0
	}
	maxDelay := 20.0 * p // ms
	delay := rand.Float64() * maxDelay
	return time.Duration(delay * float64(time.Millisecond))
}
