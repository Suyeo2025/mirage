package morph

import (
	"testing"
	"time"
)

func TestPaddingDecay(t *testing.T) {
	m := New(10.0)

	// At t=0, probability should be ~1.0
	p0 := m.PaddingProbability(0)
	if p0 < 0.99 {
		t.Fatalf("t=0: expected ~1.0, got %f", p0)
	}

	// At t=10s (one tau), probability should be ~0.37
	p10 := m.PaddingProbability(10 * time.Second)
	if p10 < 0.30 || p10 > 0.42 {
		t.Fatalf("t=10s: expected ~0.37, got %f", p10)
	}

	// At t=30s (three tau), probability should be ~0.05
	p30 := m.PaddingProbability(30 * time.Second)
	if p30 > 0.10 {
		t.Fatalf("t=30s: expected <0.10, got %f", p30)
	}

	// At t=60s, probability should be near zero
	p60 := m.PaddingProbability(60 * time.Second)
	if p60 > 0.01 {
		t.Fatalf("t=60s: expected <0.01, got %f", p60)
	}
}

func TestSampleFrameSize(t *testing.T) {
	sizes := make(map[int]int)
	for i := 0; i < 1000; i++ {
		s := SampleFrameSize()
		if s < 1 {
			t.Fatalf("frame size too small: %d", s)
		}
		// Bucket into ranges
		switch {
		case s <= 70:
			sizes[45]++
		case s <= 200:
			sizes[100]++
		case s <= 800:
			sizes[500]++
		case s <= 2000:
			sizes[1400]++
		default:
			sizes[16384]++
		}
	}

	// Each bucket should have some entries (distribution is non-degenerate)
	for _, key := range []int{45, 100, 500, 1400, 16384} {
		if sizes[key] < 20 {
			t.Errorf("bucket %d underrepresented: %d/1000", key, sizes[key])
		}
	}
}

func TestDelayDecay(t *testing.T) {
	m := New(10.0)

	// Early: should have some delay
	d0 := m.InterPacketDelay(0)
	if d0 == 0 {
		// Probabilistic, could be 0, but very unlikely at t=0
		// Run multiple times
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
	}

	// Late: should have zero delay
	d60 := m.InterPacketDelay(60 * time.Second)
	if d60 != 0 {
		t.Fatalf("expected 0 delay at t=60s, got %v", d60)
	}
}
