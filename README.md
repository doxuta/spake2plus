# spake2plus

SPAKE2+ ([RFC 9383](https://www.rfc-editor.org/rfc/rfc9383)) for Go: the augmented password-authenticated key exchange used by
Matter commissioning (PASE) and, since firmware 1.4.0, by TP-Link Tapo device logins. All seven ciphersuites that the RFC
publishes test vectors for — P-256, P-384 and P-521 with SHA-256/SHA-512, HKDF, and HMAC or CMAC-AES-128 — with every value
of every vector set pinned in the tests. Point arithmetic is [filippo.io/nistec](https://filippo.io/nistec); the rest is the
standard library.

**Unaudited.** Small by design: the primitive only, nothing above it. Read Limitations before relying on it.

## Why

Go had no SPAKE2+ at all. `crypto/ecdh` has no point addition, so a PAKE cannot be built on it; the only Go SPAKE2+ on GitHub is an
8-star proof of concept for draft-01, and the two projects that need it (go-matter, gomat) each carry a private copy. When Tapo
moved its login to SPAKE2+ in September 2026 and the Rust `tapo` maintainer reverse-engineered the handshake, every Go Tapo client
was left KLAP-only. This package is the piece they all lack.

## Install

```
go get github.com/doxuta/spake2plus
```

Requires Go 1.25 (`crypto/hkdf` and `crypto/pbkdf2`). One dependency: `filippo.io/nistec`.

## Try it

```
go run github.com/doxuta/spake2plus/cmd/spake2plus@latest
```

runs a Prover and a Verifier in one process and prints every message:

```
suite      P256-SHA256-HKDF-SHA256-HMAC-SHA256
context    "spake2plus demo P256-SHA256-HKDF-SHA256-HMAC-SHA256"
idProver   "client"
idVerifier "server"

registration record held by the Verifier
  w0 b180304bb6f521acf05dcaf968d896ca9465f3f99b535081ef8010c49fb6eed3
  L  048fee156d98e53221c045c8a961c44eb6fc8b40955290f392c90ab70eac16d768a9fdb9864bb193648827fc2ab7b5bd2d5e6ebae3283d5deebd130b91185f2e5a

Prover   -> Verifier  shareP   049f99c1d7faeb3d0ec31e600e60dcdb19e46c726083c68209104b84cef7c8916ec7eda7d7a459c56849ea0a6647e10daa79d49f29b6660da057a4413421e2948c
Verifier -> Prover    shareV   045919223f625a4cd1b0b67cc1829d15ce17b93264e8d7c98dc5ffb8d34a540797e4f84245f323532827be9eb99021539b7e58bb0596a1106cad0eebeebb4f7629
Verifier -> Prover    confirmV fd4c9c726afe2b5d0e2ee29be0ae186743f85919d615b732a26e0cb6ab1d4ea4
Prover   -> Verifier  confirmP c426452eb27ae6068f80e94067983acc5c1aadb49087128d2f2d585f875115b4

K_shared (Prover)   3d31bc2ef60e7786596e9fc0880fc10278f5240b87980942f189e36e76ea6a9d
K_shared (Verifier) 3d31bc2ef60e7786596e9fc0880fc10278f5240b87980942f189e36e76ea6a9d
equal: true
```

The shares and keys differ on every run; `w0` and `L` do not, because the demo derives them with a fixed salt. Add
`-attempt "wrong horse"` and the Prover aborts at `confirmV does not verify` without ever sending `confirmP`. `-suite` selects
any of the seven suites; `-h` lists them.

## Use it

```go
suite := spake2plus.P256SHA256HKDFHMAC

// Registration, once. The application chooses the password KDF (RFC 9383 §3.2
// recommends scrypt or Argon2id) and feeds the two halves of its output here.
w0, w1, err := suite.Scalars(kdfOut[:40], kdfOut[40:])
L, err := suite.Register(w1)
// The Verifier stores (w0, L). It never sees the password or w1.

// Online. Prover side:
p, err := suite.NewProver(context, idProver, idVerifier, w0, w1)
shareP, err := p.Start()                       // send to the Verifier
confirmP, key, err := p.Finish(shareV, confirmV) // after the Verifier's reply; send confirmP

// Verifier side:
v, err := suite.NewVerifier(context, idProver, idVerifier, w0, L)
shareV, confirmV, err := v.Exchange(shareP)    // send both to the Prover
key, err := v.Finish(confirmP)
```

Each half given to `Scalars` must be at least `suite.ScalarLen()+8` bytes (40, 56 or 74), so the reduction bias stays below
2^-64 as the RFC requires. Both `Finish` calls fail with an error, never with a wrong key, when the password, the record, the
context or an identity differs on the two sides, or when a share is off the curve, the identity element, or a tag was altered.

## What the tests pin

- `testdata/rfc9383-appendix-c.txt` is Appendix C of the RFC, verbatim. The test parses it and checks 16 values per suite:
  `L`, `shareP`, `shareV`, `Z` and `V` computed both ways, `TT`, `K_main`, `K_confirmP`, `K_confirmV`, both confirmation tags and
  `K_shared`, then runs the public API with the RFC's `x` and `y` and checks it ends on the same tags and key. 7 suites × 16 = 112
  values, plus a parser self-check so a silently dropped field cannot make a check vacuous.
- AES-CMAC against the four examples of RFC 4493.
- Round trips with random scalars on every suite; wrong w0, w1 or L on either side; altered or truncated tags; off-curve,
  identity, truncated and half-length points; scalars that are too short, too long or not below the group order; the call-order
  state machine.

Five deliberate breakages (big-endian transcript lengths, `Y + w0·N` instead of `Y − w0·N`, swapped confirmation keys, CMAC's
`Rb` constant, accepting the identity point) each turned at least one test red before the code was restored.

## Limitations

- **Not constant time for scalars.** Points are handled by nistec, which is constant time. Scalars are not: `w0`, `w1`, `x` and
  `y` are reduced modulo the group order with `math/big`, and `Scalars` is the same code path. A timing side channel on the
  password-derived values is therefore not excluded. This is the first thing to fix if the package is ever used where an attacker
  can time it.
- **Unaudited.** One author, one day, an RFC and its vectors. The vectors pin the arithmetic and the key schedule; they do not pin
  the absence of bugs in error paths or in how the caller uses the API.
- The edwards25519 and edwards448 suites of Table 1 are not implemented: the RFC publishes no test vectors for them, and this
  package does not ship what it cannot check.
- The context length prefix is always present in the transcript (zero for an empty context). The RFC allows omitting both; a
  peer that omits them will not interoperate with an empty context here.
- No cofactor handling beyond `h = 1`, which is correct for the three NIST curves and nothing else.
- No Matter or Tapo framing. Matter's PASE adds its own context hash, PBKDF parameters and session-key derivation; Tapo adds HTTP
  and AES-128-CCM. Both are layers above this package, and nothing here has been tested against a Matter or Tapo device.
- Scalars passed in are validated for length and range; they are not wiped on the caller's side. `x` and `y` and the random
  bytes they are reduced from are wiped after use, but the `math/big` reduction leaves unwiped copies on the heap, and `K_main`
  and the confirmation keys are not wiped either.

## Prior art and credits

- RFC 9383 by Tim Taubert and Christopher A. Wood, and the SPAKE2+ analysis by Shoup it rests on.
- [filippo.io/nistec](https://filippo.io/nistec) by Filippo Valsorda, which exposes the `crypto/internal/nistec` point API
  (`Add`, `Negate`, `ScalarMult`, `SetBytes`) that the standard library keeps private.
- [jtejido/spake2plus](https://github.com/jtejido/spake2plus), the earlier Go proof of concept for draft-01.
- [Mihai Dinculescu's `tapo`](https://github.com/mihai-dinculescu/tapo) (Rust), whose reverse engineering of the Tapo
  handshake in September 2026 is where the demand for a Go implementation surfaced.
- [zavan/spake2plus](https://github.com/zavan/spake2plus) and [pakery](https://github.com/djx-y-z/pakery), the Rust
  implementations from the same month.

Built with an AI coding agent under human review, in one session. The RFC vectors, not the author, are the authority on
whether the arithmetic is right.

## License

MIT.
