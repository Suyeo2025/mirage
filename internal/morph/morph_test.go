package morph

import (
	"math"
	"testing"
	"time"
)

func TestPaddingDecay(t *testing.T) {
	m := New(nil)

	p0 := m.PaddingProbability(0)
	if p0 < 0.99 {
		t.Fatalf("t=0: expected ~1.0, got %f", p0)
	}

	p10 := m.PaddingProbability(10 * time.Second)
	if p10 < 0.30 || p10 > 0.42 {
		t.Fatalf("t=10s: expected ~0.37, got %f", p10)
	}

	p30 := m.PaddingProbability(30 * time.Second)
	if p30 > 0.10 {
		t.Fatalf("t=30s: expected <0.10, got %f", p30)
	}

	p60 := m.PaddingProbability(60 * time.Second)
	if p60 > 0.01 {
		t.Fatalf("t=60s: expected <0.01, got %f", p60)
	}
}

func TestGaussianDistribution(t *testing.T) {
	// Sample many Gaussian padding sizes and verify distribution
	mu, sigma := 600, 200
	sum := 0.0
	n := 10000
	for i := 0; i < n; i++ {
		s := sampleTruncatedGaussian(mu, sigma)
		if s < 1 || s > 65535 {
			t.Fatalf("sample %d out of range: %d", i, s)
		}
		sum += float64(s)
	}

	mean := sum / float64(n)
	// Mean should be close to mu (within 3 sigma/sqrt(n))
	tolerance := 3 * float64(sigma) / math.Sqrt(float64(n))
	if math.Abs(mean-float64(mu)) > tolerance {
		t.Fatalf("mean %f too far from mu %d (tolerance %f)", mean, mu, tolerance)
	}
}

func TestGaussianVsUniformSpread(t *testing.T) {
	// Verify Gaussian produces wider spread than a uniform [min,max] of same mean
	mu, sigma := 50, 15
	buckets := make(map[int]int) // bucket by 10s
	for i := 0; i < 10000; i++ {
		s := sampleTruncatedGaussian(mu, sigma)
		buckets[s/10]++
	}
	// Should have entries in many buckets (wide spread)
	if len(buckets) < 5 {
		t.Fatalf("Gaussian spread too narrow: only %d buckets", len(buckets))
	}
}

func TestEarlyPacketAlwaysPads(t *testing.T) {
	m := New(nil)

	for i := int64(1); i <= 8; i++ {
		pad, size := m.ShouldPad(0, i)
		if !pad {
			t.Fatalf("pkt %d: expected padding in early phase", i)
		}
		if size < 1 {
			t.Fatalf("pkt %d: size %d too small", i, size)
		}
	}
}

func TestDelayDecay(t *testing.T) {
	m := New(nil)

	hasDelay := false
	for i := 0; i < 100; i++ {
		if m.InterPacketDelay(0) > 0 {
			hasDelay = true
			break
		}
	}
	if !hasDelay {
		t.Fatal("no delay at t=0 after 100 tries")
	}

	d60 := m.InterPacketDelay(60 * time.Second)
	if d60 != 0 {
		t.Fatalf("expected 0 delay at t=60s, got %v", d60)
	}
}

func TestHotConfigUpdate(t *testing.T) {
	m := New(nil)

	// Update to tau=5
	m.UpdateConfig(&Config{
		Tau:            5.0,
		EarlyPktCount:  4,
		EarlyPadMu:     300,
		EarlyPadSigma:  100,
		SteadyPadMu:    25,
		SteadyPadSigma: 8,
	})

	// At t=10s with tau=5, p should be ~0.135 (e^-2)
	p := m.PaddingProbability(10 * time.Second)
	if p < 0.10 || p > 0.18 {
		t.Fatalf("tau=5: expected p~0.135, got %f", p)
	}

	// Early packet count should be 4 now
	pad, _ := m.ShouldPad(0, 4)
	if !pad {
		t.Fatal("pkt 4 should still be early with earlyPktCount=4")
	}
}

func TestPaddingOracleInterface(t *testing.T) {
	m := New(nil)
	pad, size := m.ShouldPad(0, 1)
	if !pad {
		t.Fatal("first packet should pad")
	}
	if size <= 0 {
		t.Fatal("padding size should be positive")
	}
}

func TestTruncatedGaussianEdgeCases(t *testing.T) {
	// sigma=0 should return mu
	s := sampleTruncatedGaussian(100, 0)
	if s != 100 {
		t.Fatalf("sigma=0: expected 100, got %d", s)
	}

	// mu=0, sigma=0 should return 1 (minimum)
	s = sampleTruncatedGaussian(0, 0)
	if s != 1 {
		t.Fatalf("mu=0,sigma=0: expected 1, got %d", s)
	}
}
