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

64 KiB messages, AES-256:

| Architecture | upstream | this fork |
|---|---|---|
| amd64 | ~0.7 GB/s | ~4.8 GB/s |
| arm64 (Apple M4 Pro) | 7.6 GB/s | 7.6 GB/s |

amd64 and arm64 use hardware AES and carry-less multiplication
(detected at runtime); every other architecture falls back to a
pure-Go implementation, as does the `purego` build tag.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in an
implementation, please create a GitHub issue.

### Disclaimer

The upstream author's disclaimer applies to this fork as well: use
cryptography libraries that have been reviewed by cryptographers.
This fork has not been independently audited.
