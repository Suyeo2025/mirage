package carrier

import (
	"strings"
	"testing"
)

func TestValidateRealityClientConfig(t *testing.T) {
	// Production REALITY key from the deployed mirror — exactly 32 bytes
	// after base64 decode, exactly 8 bytes after hex decode. Used as the
	// "happy path" reference so the validator is sanity-checked against
	// real credentials rather than fixtures only.
	const goodPub = "YSm9DHlu8Ofju69FtXN9gncd3yDLjDRD8b_0QIk0l2s"
	const goodSID = "a168fb3c2dd62c66"

	t.Run("good", func(t *testing.T) {
		pub, sid, err := validateRealityClientConfig(goodPub, goodSID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pub) != 32 {
			t.Errorf("pub len = %d, want 32", len(pub))
		}
		if len(sid) != 8 {
			t.Errorf("sid len = %d, want 8", len(sid))
		}
	})

	t.Run("bad base64", func(t *testing.T) {
		_, _, err := validateRealityClientConfig("not-base64!!", goodSID)
		if err == nil || !strings.Contains(err.Error(), "base64") {
			t.Errorf("expected base64 error, got %v", err)
		}
	})

	t.Run("wrong pubkey length", func(t *testing.T) {
		// 16 bytes of base64 instead of 32
		_, _, err := validateRealityClientConfig("AAAAAAAAAAAAAAAAAAAAAA", goodSID)
		if err == nil || !strings.Contains(err.Error(), "length") {
			t.Errorf("expected length error, got %v", err)
		}
	})

	t.Run("bad hex", func(t *testing.T) {
		_, _, err := validateRealityClientConfig(goodPub, "zzzz")
		if err == nil || !strings.Contains(err.Error(), "hex") {
			t.Errorf("expected hex error, got %v", err)
		}
	})

	t.Run("short-id too long", func(t *testing.T) {
		// 10 bytes hex = 20 hex chars, > 8 bytes
		_, _, err := validateRealityClientConfig(goodPub, "00112233445566778899aabbccddeeff11")
		if err == nil || !strings.Contains(err.Error(), "max 8") {
			t.Errorf("expected length error, got %v", err)
		}
	})

	t.Run("short-id shorter than 8 is fine", func(t *testing.T) {
		// REALITY supports 0-8 byte short ids; the rest is zero-padded.
		_, sid, err := validateRealityClientConfig(goodPub, "0011")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sid) != 2 {
			t.Errorf("sid len = %d, want 2", len(sid))
		}
	})
}
