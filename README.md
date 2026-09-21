# AES-GCM-SIV

Nonce misuse-resistant AEAD (RFC 8452).

This is [PlakarKorp](https://github.com/PlakarKorp)'s fork of
[ericlagergren/siv](https://github.com/ericlagergren/siv). It carries
changes needed for our use cases — primarily performance work on the
data path used by [plakar](https://github.com/PlakarKorp/plakar) and
[kloset](https://github.com/PlakarKorp/kloset):

- pipelined multi-block AES-CTR assembly for amd64, from upstream
  [PR #7](https://github.com/ericlagergren/siv/pull/7) by Boris Nagaev
  (upstream already has the arm64 equivalent)
- module path renamed to `github.com/PlakarKorp/aes-gcm-siv` so the
  fork can be imported directly

The wire format is unchanged: ciphertext is interoperable with
upstream and with other RFC 8452 implementations.

References:

- https://datatracker.ietf.org/doc/html/rfc8452
- https://eprint.iacr.org/2017/168.pdf
- https://eprint.iacr.org/2015/102.pdf

## Installation

```bash
go get github.com/PlakarKorp/aes-gcm-siv@latest
```

## Performance

amd64 and arm64 use hardware AES and carry-less multiplication
(detected at runtime); every other architecture falls back to a
pure-Go implementation, as does the `purego` build tag.

Reproduce with:

```bash
go test -run xxx -bench AES_GCM -benchtime 2s .
```

Apple M4 Pro (arm64), AES-GCM-SIV with stdlib AES-GCM as the
non-SIV baseline:

```
goos: darwin
goarch: arm64
cpu: Apple M4 Pro
BenchmarkSeal1K_AES_GCM_SIV_128-14      312.0 ns/op   3281.67 MB/s
BenchmarkOpen1K_AES_GCM_SIV_128-14      308.7 ns/op   3317.19 MB/s
BenchmarkSeal8K_AES_GCM_SIV_128-14      1107 ns/op    7397.38 MB/s
BenchmarkOpen8K_AES_GCM_SIV_128-14      1093 ns/op    7492.96 MB/s
BenchmarkSeal64K_AES_GCM_SIV_128-14     7446 ns/op    8801.41 MB/s
BenchmarkOpen64K_AES_GCM_SIV_128-14     7398 ns/op    8858.73 MB/s
BenchmarkSeal1K_AES_GCM_SIV_256-14      359.1 ns/op   2851.52 MB/s
BenchmarkOpen1K_AES_GCM_SIV_256-14      364.1 ns/op   2812.14 MB/s
BenchmarkSeal8K_AES_GCM_SIV_256-14      1265 ns/op    6476.58 MB/s
BenchmarkOpen8K_AES_GCM_SIV_256-14      1255 ns/op    6527.28 MB/s
BenchmarkSeal64K_AES_GCM_SIV_256-14     8525 ns/op    7687.10 MB/s
BenchmarkOpen64K_AES_GCM_SIV_256-14     8614 ns/op    7607.64 MB/s

BenchmarkSeal64K_AES_GCM_128-14         7081 ns/op    9255.82 MB/s
BenchmarkOpen64K_AES_GCM_128-14         6652 ns/op    9852.05 MB/s
BenchmarkSeal64K_AES_GCM_256-14         8308 ns/op    7888.17 MB/s
BenchmarkOpen64K_AES_GCM_256-14         7745 ns/op    8461.58 MB/s
```

At 64 KiB (the chunk size kloset uses), AES-256-GCM-SIV runs within
~3-4% of stdlib AES-256-GCM while adding nonce misuse resistance.

On amd64 the pipelined CTR kernel from
[upstream PR #7](https://github.com/ericlagergren/siv/pull/7) gives
roughly 3.5-4x over the single-block upstream code on real x86
hardware; see the PR for measurements.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in an
implementation, please create a GitHub issue.

### Disclaimer

The upstream author's disclaimer applies to this fork as well: use
cryptography libraries that have been reviewed by cryptographers.
This fork has not been independently audited.
