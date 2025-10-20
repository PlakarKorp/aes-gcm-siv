//go:build gc && !purego

package siv

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc *uint32)

//go:noescape
func leCtrBlocks1Asm(nr int, xk *uint32, dst *[blockSize]byte, src *[blockSize]byte, block *[TagSize]byte)

//go:noescape
func leCtrBlocks2Asm(nr int, xk *uint32, dst *[2 * blockSize]byte, src *[2 * blockSize]byte, block *[TagSize]byte)

//go:noescape
func leCtrBlocks4Asm(nr int, xk *uint32, dst *[4 * blockSize]byte, src *[4 * blockSize]byte, block *[TagSize]byte)

//go:noescape
func leCtrBlocks8Asm(nr int, xk *uint32, dst *[8 * blockSize]byte, src *[8 * blockSize]byte, block *[TagSize]byte)
