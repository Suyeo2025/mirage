package auth

import (
	"testing"
	"time"
)

func TestTokenRoundTrip(t *testing.T) {
	a := New("test-psk")
	sid := make([]byte, 16)
	copy(sid, []byte("test-session-id!"))

	token, err := a.Generate(1, sid)
	if err != nil {
		t.Fatal(err)
	}

	userID, gotSID, err := a.Validate(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if userID != 1 {
		t.Fatalf("userID: got %d want 1", userID)
	}
	if string(gotSID) != string(sid) {
		t.Fatalf("sessionID mismatch")
	}
}

func TestTokenReplay(t *testing.T) {
	a := New("test-psk-replay")
	token, _ := a.Generate(1, make([]byte, 16))
	if _, _, err := a.Validate(token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Validate(token); err == nil {
		t.Fatal("replay should fail")
	}
}

func TestTokenExpired(t *testing.T) {
	a := New("test-psk-expire")
	a.maxAge = 1 * time.Second
	token, _ := a.Generate(1, make([]byte, 16))
	time.Sleep(2 * time.Second)
	if _, _, err := a.Validate(token); err == nil {
		t.Fatal("expired should fail")
	}
}

func TestTokenWrongPSK(t *testing.T) {
	a1 := New("psk-one")
	a2 := New("psk-two")
	token, _ := a1.Generate(1, make([]byte, 16))
	if _, _, err := a2.Validate(token); err == nil {
		t.Fatal("wrong PSK should fail")
	}
}
