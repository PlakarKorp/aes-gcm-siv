//go:build (amd64 || arm64) && gc && !purego

package siv

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"testing"
)

// TestAesctrCounterWrap compares the assembly CTR path against the
// generic one with the 32-bit counter parked just below 2^32, so the
// wrap happens inside a multi-block batch. Random tags make this case
// vanishingly rare in the other tests.
func TestAesctrCounterWrap(t *testing.T) {
	if !haveAsm {
		t.Skip("no assembly on this platform")
	}
	starts := []uint32{
		0x00000000,
		0xffffffff, // wraps after the first block
		0xfffffffe, // wraps inside a 2-block batch
		0xfffffffd, // wraps inside a 4-block batch
		0xfffffff9, // wraps inside an 8-block batch
	}
	sizes := []int{1, 15, 16, 31, 32, 33, 64, 96, 127, 128, 129, 160, 256, 4096}
	for _, keyLen := range []int{16, 32} {
		key := randbuf(keyLen)
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		nr := 6 + keyLen/4
		var enc [maxEncSize]uint32
		expandKeyAsm(nr, &key[0], &enc[0])

		for _, start := range starts {
			tag := randbuf(TagSize)
			binary.LittleEndian.PutUint32(tag[0:4], start)
			tag[15] &= 0x7f // as produced by sum()
			for _, n := range sizes {
				t.Run(fmt.Sprintf("key%d/ctr%08x/len%d", keyLen*8, start, n), func(t *testing.T) {
					src := randbuf(n)

					want := make([]byte, n)
					aesctrGeneric(block, tag, want, src)

					got := make([]byte, n)
					var ctrBlock [TagSize]byte
					copy(ctrBlock[:], tag)
					ctrBlock[15] |= 0x80
					aesctr(nr, &enc[0], &ctrBlock, got, src)

					if !bytes.Equal(got, want) {
						t.Errorf("assembly and generic CTR disagree")
					}
				})
			}
		}
	}
}
