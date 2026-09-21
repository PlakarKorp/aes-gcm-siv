package siv

import (
	"testing"
)

// TestAEADSizes checks the cipher.AEAD size accessors.
func TestAEADSizes(t *testing.T) {
	for _, n := range []int{16, 32} {
		aead, err := NewGCM(randbuf(n))
		if err != nil {
			t.Fatal(err)
		}
		if got := aead.NonceSize(); got != NonceSize {
			t.Errorf("NonceSize: got %d, want %d", got, NonceSize)
		}
		if got := aead.Overhead(); got != TagSize {
			t.Errorf("Overhead: got %d, want %d", got, TagSize)
		}
	}
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		t.Helper()
		if recover() == nil {
			t.Errorf("%s: expected panic", name)
		}
	}()
	fn()
}

// TestSealPanics checks Seal's misuse guards.
func TestSealPanics(t *testing.T) {
	runTests(t, func(t *testing.T) {
		aead, err := NewGCM(randbuf(32))
		if err != nil {
			t.Fatal(err)
		}
		mustPanic(t, "short nonce", func() {
			aead.Seal(nil, randbuf(NonceSize-1), randbuf(16), nil)
		})
		mustPanic(t, "long nonce", func() {
			aead.Seal(nil, randbuf(NonceSize+1), randbuf(16), nil)
		})
		mustPanic(t, "inexact overlap", func() {
			buf := randbuf(64)
			// out = buf[0:32] overlaps plaintext = buf[16:32]
			// without sharing a start address.
			aead.Seal(buf[:0], randbuf(NonceSize), buf[16:32], nil)
		})
	})
}

// TestOpenPanics checks Open's misuse guards.
func TestOpenPanics(t *testing.T) {
	runTests(t, func(t *testing.T) {
		aead, err := NewGCM(randbuf(32))
		if err != nil {
			t.Fatal(err)
		}
		mustPanic(t, "short nonce", func() {
			aead.Open(nil, randbuf(NonceSize-1), randbuf(32), nil)
		})
		mustPanic(t, "long nonce", func() {
			aead.Open(nil, randbuf(NonceSize+1), randbuf(32), nil)
		})
		mustPanic(t, "inexact overlap", func() {
			buf := randbuf(64)
			// out = buf[0:16] overlaps ciphertext = buf[8:40]
			// without sharing a start address.
			aead.Open(buf[:0], randbuf(NonceSize), buf[8:40], nil)
		})
	})
}

// TestOpenRejects checks Open's error (non-panic) input checks.
func TestOpenRejects(t *testing.T) {
	runTests(t, func(t *testing.T) {
		aead, err := NewGCM(randbuf(32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aead.Open(nil, randbuf(NonceSize), randbuf(TagSize-1), nil); err == nil {
			t.Error("expected error for ciphertext shorter than the tag")
		}
	})
}
