// Package spake2plus implements SPAKE2+, the augmented password-authenticated
// key exchange of RFC 9383, over the NIST curves on filippo.io/nistec.
//
// A Prover (the party that knows the password) and a Verifier (the party that
// stores the registration record w0, L) exchange one key share each and one
// confirmation tag each, and end with the same K_shared or with an error.
//
// Point arithmetic is constant time (nistec). Scalar handling is not: w0, w1,
// x and y are reduced with math/big. The package has not been audited.
package spake2plus

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"filippo.io/nistec"
)

// nistPoint is the subset of the nistec point API the protocol needs.
type nistPoint[P any] interface {
	Add(p1, p2 P) P
	Negate(p P) P
	ScalarMult(q P, scalar []byte) (P, error)
	ScalarBaseMult(scalar []byte) (P, error)
	SetBytes(b []byte) (P, error)
	Bytes() []byte
	IsInfinity() int
}

// group is one prime-order NIST curve, with every operation expressed on
// uncompressed SEC 1 encodings so the suites can share one code path.
type group struct {
	scalarLen int
	order     *big.Int
	base      func(k []byte) ([]byte, error)    // k*P
	mul       func(p, k []byte) ([]byte, error) // k*p
	add       func(p, q []byte) ([]byte, error) // p + q
	sub       func(p, q []byte) ([]byte, error) // p - q
	check     func(p []byte) error              // on the curve and not the identity
}

func newGroup[P nistPoint[P]](newPoint func() P, orderHex string, scalarLen int) *group {
	order, ok := new(big.Int).SetString(orderHex, 16)
	if !ok {
		panic("spake2plus: bad group order")
	}
	parse := func(b []byte) (P, error) {
		p, err := newPoint().SetBytes(b)
		if err != nil {
			return p, fmt.Errorf("spake2plus: %w", err)
		}
		if p.IsInfinity() == 1 {
			return p, errors.New("spake2plus: point is the identity")
		}
		return p, nil
	}
	two := func(p, q []byte) (P, P, error) {
		pp, err := parse(p)
		if err != nil {
			return pp, pp, err
		}
		qq, err := parse(q)
		return pp, qq, err
	}
	return &group{
		scalarLen: scalarLen,
		order:     order,
		base: func(k []byte) ([]byte, error) {
			r, err := newPoint().ScalarBaseMult(k)
			if err != nil {
				return nil, err
			}
			return r.Bytes(), nil
		},
		mul: func(p, k []byte) ([]byte, error) {
			pp, err := parse(p)
			if err != nil {
				return nil, err
			}
			r, err := newPoint().ScalarMult(pp, k)
			if err != nil {
				return nil, err
			}
			return r.Bytes(), nil
		},
		add: func(p, q []byte) ([]byte, error) {
			pp, qq, err := two(p, q)
			if err != nil {
				return nil, err
			}
			return newPoint().Add(pp, qq).Bytes(), nil
		},
		sub: func(p, q []byte) ([]byte, error) {
			pp, qq, err := two(p, q)
			if err != nil {
				return nil, err
			}
			return newPoint().Add(pp, newPoint().Negate(qq)).Bytes(), nil
		},
		check: func(p []byte) error {
			_, err := parse(p)
			return err
		},
	}
}

// reduce interprets b as a big-endian integer and returns it mod the group
// order as a fixed-length scalar. Not constant time.
func (g *group) reduce(b []byte) []byte {
	k := new(big.Int).SetBytes(b)
	k.Mod(k, g.order)
	return k.FillBytes(make([]byte, g.scalarLen))
}

// checkScalar accepts exactly scalarLen bytes encoding a value in [0, order).
func (g *group) checkScalar(name string, k []byte) error {
	if len(k) != g.scalarLen {
		return fmt.Errorf("spake2plus: %s must be %d bytes, got %d", name, g.scalarLen, len(k))
	}
	if new(big.Int).SetBytes(k).Cmp(g.order) >= 0 {
		return fmt.Errorf("spake2plus: %s is not below the group order", name)
	}
	return nil
}

func (g *group) randomScalar() []byte {
	buf := make([]byte, g.scalarLen+8) // 64 extra bits: bias below 2^-64 (RFC 9383 §3.2)
	rand.Read(buf)
	defer clear(buf) // buf determines the scalar, so it is as secret
	return g.reduce(buf)
}

var (
	p256 = newGroup(nistec.NewP256Point, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 32)
	p384 = newGroup(nistec.NewP384Point, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 48)
	p521 = newGroup(nistec.NewP521Point, "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 66)
)

// Suite is one SPAKE2+ ciphersuite from RFC 9383 Table 1.
type Suite struct {
	// Name is the suite's name as it appears in the RFC's test vectors,
	// e.g. "P256-SHA256-HKDF-SHA256-HMAC-SHA256".
	Name string

	g         *group
	hash      func() hash.Hash
	macKeyLen int  // per confirmation key
	cmac      bool // CMAC-AES-128 instead of HMAC
	m, n      []byte
}

func suite(name string, g *group, h func() hash.Hash, cmac bool, mHex, nHex string) *Suite {
	s := &Suite{Name: name, g: g, hash: h, cmac: cmac, macKeyLen: h().Size()}
	if cmac {
		s.macKeyLen = 16
	}
	var err error
	// Table 1 gives M and N compressed; the transcript carries them uncompressed.
	if s.m, err = g.mul(unhex(mHex), one(g)); err != nil {
		panic(err)
	}
	if s.n, err = g.mul(unhex(nHex), one(g)); err != nil {
		panic(err)
	}
	return s
}

func one(g *group) []byte { b := make([]byte, g.scalarLen); b[len(b)-1] = 1; return b }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

const (
	p256M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
	p256N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
	p384M = "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853"
	p384N = "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10"
	p521M = "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa"
	p521N = "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25"
)

// The seven ciphersuites that RFC 9383 Appendix C provides test vectors for.
var (
	P256SHA256HKDFHMAC = suite("P256-SHA256-HKDF-SHA256-HMAC-SHA256", p256, sha256.New, false, p256M, p256N)
	P256SHA512HKDFHMAC = suite("P256-SHA512-HKDF-SHA512-HMAC-SHA512", p256, sha512.New, false, p256M, p256N)
	P384SHA256HKDFHMAC = suite("P384-SHA256-HKDF-SHA256-HMAC-SHA256", p384, sha256.New, false, p384M, p384N)
	P384SHA512HKDFHMAC = suite("P384-SHA512-HKDF-SHA512-HMAC-SHA512", p384, sha512.New, false, p384M, p384N)
	P521SHA512HKDFHMAC = suite("P521-SHA512-HKDF-SHA512-HMAC-SHA512", p521, sha512.New, false, p521M, p521N)
	P256SHA256HKDFCMAC = suite("P256-SHA256-HKDF-SHA256-CMAC-AES-128", p256, sha256.New, true, p256M, p256N)
	P256SHA512HKDFCMAC = suite("P256-SHA512-HKDF-SHA512-CMAC-AES-128", p256, sha512.New, true, p256M, p256N)
)

// Suites lists every suite in this package, in RFC 9383 Appendix C order.
var Suites = []*Suite{
	P256SHA256HKDFHMAC, P256SHA512HKDFHMAC,
	P384SHA256HKDFHMAC, P384SHA512HKDFHMAC,
	P521SHA512HKDFHMAC,
	P256SHA256HKDFCMAC, P256SHA512HKDFCMAC,
}

// ScalarLen is the byte length of w0, w1 and the registration record's
// scalars for this suite (32, 48 or 66).
func (s *Suite) ScalarLen() int { return s.g.scalarLen }

// Scalars turns the two halves of a password-based KDF output into w0 and w1
// (RFC 9383 §3.2): each half is reduced modulo the group order. Each half must
// be at least ScalarLen()+8 bytes so the reduction bias stays below 2^-64. The
// choice of KDF, its parameters and the salt are the application's.
func (s *Suite) Scalars(w0s, w1s []byte) (w0, w1 []byte, err error) {
	min := s.g.scalarLen + 8
	if len(w0s) < min || len(w1s) < min {
		return nil, nil, fmt.Errorf("spake2plus: each KDF half must be at least %d bytes", min)
	}
	return s.g.reduce(w0s), s.g.reduce(w1s), nil
}

// Register computes the registration record L = w1*P that the Verifier stores
// next to w0. The Verifier never learns w1.
func (s *Suite) Register(w1 []byte) (L []byte, err error) {
	if err := s.g.checkScalar("w1", w1); err != nil {
		return nil, err
	}
	return s.g.base(w1)
}

// Prover is the party that knows the password (w0 and w1).
type Prover struct {
	s             *Suite
	ctx, idP, idV []byte
	w0, w1        []byte
	x, shareP     []byte
	started, done bool
}

// NewProver prepares a Prover. context is the application's customization
// string (may be empty); idProver and idVerifier are the identities that went
// into w0 and w1 (either may be empty, see RFC 9383 §3.3 on unknown key-share
// attacks).
func (s *Suite) NewProver(context, idProver, idVerifier, w0, w1 []byte) (*Prover, error) {
	if err := s.g.checkScalar("w0", w0); err != nil {
		return nil, err
	}
	if err := s.g.checkScalar("w1", w1); err != nil {
		return nil, err
	}
	return &Prover{s: s, ctx: context, idP: idProver, idV: idVerifier, w0: w0, w1: w1}, nil
}

// Start returns shareP = x*P + w0*M for a fresh random x.
func (p *Prover) Start() (shareP []byte, err error) {
	return p.start(p.s.g.randomScalar())
}

func (p *Prover) start(x []byte) ([]byte, error) {
	if p.started {
		return nil, errors.New("spake2plus: Start called twice")
	}
	xP, err := p.s.g.base(x)
	if err != nil {
		return nil, err
	}
	w0M, err := p.s.g.mul(p.s.m, p.w0)
	if err != nil {
		return nil, err
	}
	p.shareP, err = p.s.g.add(xP, w0M)
	if err != nil {
		return nil, err
	}
	p.x, p.started = x, true // takes ownership of x: Finish wipes it
	return p.shareP, nil
}

// Finish consumes the Verifier's shareV and confirmV. It returns confirmP for
// the Verifier and the shared key, or an error if shareV is not a valid group
// element or confirmV does not verify (wrong password, wrong record or tampering).
func (p *Prover) Finish(shareV, confirmV []byte) (confirmP, sharedKey []byte, err error) {
	if !p.started || p.done {
		return nil, nil, errors.New("spake2plus: Finish must follow Start, once")
	}
	p.done = true
	defer clear(p.x)
	g := p.s.g
	w0N, err := g.mul(p.s.n, p.w0)
	if err != nil {
		return nil, nil, err
	}
	t, err := g.sub(shareV, w0N) // Y - w0*N; fails if Y is off-curve or the identity
	if err != nil {
		return nil, nil, err
	}
	z, err := g.mul(t, p.x) // h = 1 for the NIST curves
	if err != nil {
		return nil, nil, err
	}
	v, err := g.mul(t, p.w1)
	if err != nil {
		return nil, nil, err
	}
	k, err := p.s.keys(transcript(p.ctx, p.idP, p.idV, p.s.m, p.s.n, p.shareP, shareV, z, v, p.w0))
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(confirmV, p.s.mac(k.confirmV, p.shareP)) != 1 {
		return nil, nil, errors.New("spake2plus: confirmV does not verify")
	}
	return p.s.mac(k.confirmP, shareV), k.shared, nil
}

// Verifier is the party that stores the registration record (w0, L).
type Verifier struct {
	s             *Suite
	ctx, idP, idV []byte
	w0, l         []byte
	shareV        []byte
	confirmP      []byte
	shared        []byte
	exchanged     bool
	done          bool
}

// NewVerifier prepares a Verifier from the stored record.
func (s *Suite) NewVerifier(context, idProver, idVerifier, w0, L []byte) (*Verifier, error) {
	if err := s.g.checkScalar("w0", w0); err != nil {
		return nil, err
	}
	if err := s.g.check(L); err != nil {
		return nil, fmt.Errorf("L: %w", err)
	}
	return &Verifier{s: s, ctx: context, idP: idProver, idV: idVerifier, w0: w0, l: L}, nil
}

// Exchange consumes the Prover's shareP and returns shareV and confirmV.
func (v *Verifier) Exchange(shareP []byte) (shareV, confirmV []byte, err error) {
	return v.exchange(shareP, v.s.g.randomScalar())
}

func (v *Verifier) exchange(shareP, y []byte) ([]byte, []byte, error) {
	if v.exchanged {
		return nil, nil, errors.New("spake2plus: Exchange called twice")
	}
	defer clear(y) // takes ownership of y: wiped on return
	g := v.s.g
	yP, err := g.base(y)
	if err != nil {
		return nil, nil, err
	}
	w0N, err := g.mul(v.s.n, v.w0)
	if err != nil {
		return nil, nil, err
	}
	if v.shareV, err = g.add(yP, w0N); err != nil {
		return nil, nil, err
	}
	w0M, err := g.mul(v.s.m, v.w0)
	if err != nil {
		return nil, nil, err
	}
	t, err := g.sub(shareP, w0M) // X - w0*M; fails if X is off-curve or the identity
	if err != nil {
		return nil, nil, err
	}
	z, err := g.mul(t, y)
	if err != nil {
		return nil, nil, err
	}
	vv, err := g.mul(v.l, y)
	if err != nil {
		return nil, nil, err
	}
	k, err := v.s.keys(transcript(v.ctx, v.idP, v.idV, v.s.m, v.s.n, shareP, v.shareV, z, vv, v.w0))
	if err != nil {
		return nil, nil, err
	}
	// Only a completed exchange may be followed by Finish: a rejected shareP
	// leaves no expected confirmP to compare against.
	v.confirmP, v.shared, v.exchanged = v.s.mac(k.confirmP, v.shareV), k.shared, true
	return v.shareV, v.s.mac(k.confirmV, shareP), nil
}

// Finish checks the Prover's confirmP and returns the shared key.
func (v *Verifier) Finish(confirmP []byte) (sharedKey []byte, err error) {
	if !v.exchanged || v.done {
		return nil, errors.New("spake2plus: Finish must follow Exchange, once")
	}
	v.done = true
	defer clear(v.confirmP)
	if subtle.ConstantTimeCompare(confirmP, v.confirmP) != 1 {
		return nil, errors.New("spake2plus: confirmP does not verify")
	}
	return v.shared, nil
}

// transcript builds TT (RFC 9383 §3.3): every field is prefixed with its
// length as a 64-bit little-endian integer. The context prefix is always
// present, as a zero length when the context is empty.
func transcript(fields ...[]byte) []byte {
	var tt []byte
	for _, f := range fields {
		tt = binary.LittleEndian.AppendUint64(tt, uint64(len(f)))
		tt = append(tt, f...)
	}
	return tt
}

type keySchedule struct{ confirmP, confirmV, shared []byte }

// keys is the key schedule of RFC 9383 §3.4.
func (s *Suite) keys(tt []byte) (keySchedule, error) {
	h := s.hash()
	h.Write(tt)
	kMain := h.Sum(nil)
	conf, err := hkdf.Key(s.hash, kMain, nil, "ConfirmationKeys", 2*s.macKeyLen)
	if err != nil {
		return keySchedule{}, err
	}
	shared, err := hkdf.Key(s.hash, kMain, nil, "SharedKey", h.Size())
	if err != nil {
		return keySchedule{}, err
	}
	return keySchedule{confirmP: conf[:s.macKeyLen], confirmV: conf[s.macKeyLen:], shared: shared}, nil
}

func (s *Suite) mac(key, msg []byte) []byte {
	if s.cmac {
		return cmacAES(key, msg)
	}
	m := hmac.New(s.hash, key)
	m.Write(msg)
	return m.Sum(nil)
}
