// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"sync"

	_ "github.com/ericlagergren/siv"
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run . -out ../../ctr_amd64.s

var littleEndian = flag.Bool("le", false, "generate little-endian counter layout")

func main() {
	flag.Parse()

	pkgPath := "crypto/internal/fips140/aes"
	if f := flag.Lookup("pkg"); f != nil && f.Value.String() != "" {
		pkgPath = f.Value.String()
	}
	Package(pkgPath)
	ConstraintExpr("!purego")

	for _, blocks := range []int{1, 2, 4, 8} {
		ctrBlocks(blocks, *littleEndian)
	}

	Generate()
}

func ctrBlocks(numBlocks int, le bool) {
	name := fmt.Sprintf("ctrBlocks%dAsm", numBlocks)
	if le {
		name = fmt.Sprintf("leCtrBlocks%dAsm", numBlocks)
	}
	Implement(name)

	rounds := Load(Param("nr"), GP64())
	xk := Load(Param("xk"), GP64())
	dst := Load(Param("dst"), GP64())
	src := Load(Param("src"), GP64())

	var blocks []VecVirtual
	if le {
		ctr := Load(Param("block"), GP64())
		blocks = ctrBlocksLittleEndian(numBlocks, ctr)
	} else {
		ivlo := Load(Param("ivlo"), GP64())
		ivhi := Load(Param("ivhi"), GP64())
		blocks = ctrBlocksBigEndian(numBlocks, ivlo, ivhi)
	}

	// Initial key add.
	aesRoundStart(blocks, Mem{Base: xk})
	ADDQ(Imm(16), xk)

	// Branch based on the number of rounds.
	SUBQ(Imm(12), rounds)
	JE(LabelRef("enc192"))
	JB(LabelRef("enc128"))

	// Two extra rounds for 256-bit keys.
	aesRound(blocks, Mem{Base: xk})
	aesRound(blocks, Mem{Base: xk}.Offset(16))
	ADDQ(Imm(32), xk)

	// Two extra rounds for 192-bit keys.
	Label("enc192")
	aesRound(blocks, Mem{Base: xk})
	aesRound(blocks, Mem{Base: xk}.Offset(16))
	ADDQ(Imm(32), xk)

	// 10 rounds for 128-bit keys (with special handling for the final round).
	Label("enc128")
	for i := 0; i < 9; i++ {
		aesRound(blocks, Mem{Base: xk}.Offset(16*i))
	}
	aesRoundLast(blocks, Mem{Base: xk}.Offset(16*9))

	// XOR state with src and write back to dst.
	for i, b := range blocks {
		x := XMM()

		MOVUPS(Mem{Base: src}.Offset(16*i), x)
		PXOR(b, x)
		MOVUPS(x, Mem{Base: dst}.Offset(16*i))
	}

	RET()
}

// ctrBlocksBigEndian materialises the numBlocks counter blocks for the
// original (GCM) layout where the counter is a big-endian 16-byte number.
//
// This path is used when we are generating ctrBlocks*Asm functions used in
// AES CTR mode. The caller passes IV+counter as two 64-bit integers: ivhi and
// ivlo. We increment ivlo and a carry into ivhi, and we use PSHUFB to turn
// them into a big-endian 16-byte number in an XMM register.
func ctrBlocksBigEndian(numBlocks int, ivlo, ivhi Register) []VecVirtual {
	bswap := XMM()
	MOVOU(bswapMask(), bswap)

	blocks := make([]VecVirtual, 0, numBlocks)
	for i := 0; i < numBlocks; i++ {
		x := XMM()
		blocks = append(blocks, x)

		MOVQ(ivlo, x)
		PINSRQ(Imm(1), ivhi, x)
		PSHUFB(bswap, x)
		if i < numBlocks-1 {
			ADDQ(Imm(1), ivlo)
			ADCQ(Imm(0), ivhi)
		}
	}
	return blocks
}

// ctrBlocksLittleEndian builds numBlocks counter blocks for AES-GCM-SIV. The
// caller passes a pointer to the 16-byte block (blockPtr), which is the
// little-endian 4 byte word, followed by fixed 12 bytes. We generate the
// sequence of counter blocks in registers using PADDD with the constants
// produced by leDeltaMem, and we update the in-memory counter by adding
// numBlocks (mod 2^32) so the Go code sees the expected next counter.
func ctrBlocksLittleEndian(numBlocks int, blockPtr Register) []VecVirtual {
	blocks := make([]VecVirtual, 0, numBlocks)

	base := XMM()
	MOVOU(Mem{Base: blockPtr}, base)
	blocks = append(blocks, base)
	for i := 1; i < numBlocks; i++ {
		x := XMM()
		MOVAPS(base, x)
		PADDD(leDeltaMem(i), x)
		blocks = append(blocks, x)
	}

	// Increment the counter in the block passed by pointer.
	tmp := GP32()
	MOVL(Mem{Base: blockPtr}, tmp)
	ADDL(Imm(uint64(numBlocks)), tmp)
	MOVL(tmp, Mem{Base: blockPtr})

	return blocks
}

func aesRoundStart(blocks []VecVirtual, k Mem) {
	x := XMM()
	MOVUPS(k, x)
	for _, b := range blocks {
		PXOR(x, b)
	}
}

func aesRound(blocks []VecVirtual, k Mem) {
	x := XMM()
	MOVUPS(k, x)
	for _, b := range blocks {
		AESENC(x, b)
	}
}

func aesRoundLast(blocks []VecVirtual, k Mem) {
	x := XMM()
	MOVUPS(k, x)
	for _, b := range blocks {
		AESENCLAST(x, b)
	}
}

var bswapMask = sync.OnceValue(func() Mem {
	bswapMask := GLOBL("bswapMask", NOPTR|RODATA)
	DATA(0x00, U64(0x08090a0b0c0d0e0f))
	DATA(0x08, U64(0x0001020304050607))
	return bswapMask
})

// leDeltaCache caches the constant vectors used to bump the low counter lane.
var leDeltaCache = make(map[int]Mem)

// leDeltaMem returns a 128-bit constant where the low 32 bits contain v and
// the remaining lanes are zero. PADDDing this constant to a counter block
// increases just the counter lane. We cache the constants because a generator
// run is likely to request the same small offsets repeatedly.
func leDeltaMem(v int) Mem {
	if mem, ok := leDeltaCache[v]; ok {
		return mem
	}

	name := fmt.Sprintf("leCtrDelta_%d", v)
	delta := GLOBL(name, NOPTR|RODATA)
	DATA(0x00, U32(uint32(v)))
	DATA(0x04, U32(0))
	DATA(0x08, U32(0))
	DATA(0x0C, U32(0))
	leDeltaCache[v] = delta

	return delta
}
