package spake2plus

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestFinishAfterFailedExchange: a Verifier whose Exchange rejected shareP
// has no confirmation key, so Finish must refuse to run (RFC 9383 §3.1: the
// protocol is not complete before a key confirmation message has been
// received and validated). Before the fix the state machine marked the
// Verifier as exchanged on entry, and Finish compared the peer's tag with a
// nil expected tag: an empty confirmP "verified" and yielded a nil key.
func TestFinishAfterFailedExchange(t *testing.T) {
	s := P256SHA256HKDFHMAC
	w0, w1 := randomScalars(t, s)
	L, _ := s.Register(w1)
	for name, bad := range map[string][]byte{"identity": {0x00}, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			v, _ := s.NewVerifier(nil, nil, nil, w0, L)
			if _, _, err := v.Exchange(bad); err == nil {
				t.Fatal("Exchange accepted a bad shareP")
			}
			for _, tag := range [][]byte{nil, {}} {
				key, err := v.Finish(tag)
				if err == nil || key != nil {
					t.Errorf("Finish(%x) after a failed Exchange: key=%x err=%v, want an error", tag, key, err)
				}
			}
		})
	}
}

// TestTranscriptEmptyFields pins the RFC 9383 §3.3 encoding of absent
// context and identities: each is still present as an 8-byte little-endian
// zero length followed by nothing. Appendix C only exercises non-empty
// values, and the round-trip tests cannot see a symmetric encoding change
// (both sides would skip the field alike), so this is the only check that
// an "omit empty fields" change would turn red. Matter PASE, the main
// consumer, runs with empty identities.
func TestTranscriptEmptyFields(t *testing.T) {
	s := P256SHA256HKDFHMAC
	w0, w1 := randomScalars(t, s)
	L, _ := s.Register(w1)
	var x, y []byte
	for i := 0; i < 2 && len(x) == 0; i++ { // never zero in practice; guard anyway
		x, y = s.g.randomScalar(), s.g.randomScalar()
	}
	p, _ := s.NewProver(nil, nil, nil, w0, w1)
	v, _ := s.NewVerifier(nil, nil, nil, w0, L)
	shareP, _ := p.start(bytes.Clone(x))
	shareV, confirmV, _ := v.exchange(shareP, bytes.Clone(y))
	w0N, _ := s.g.mul(s.n, w0)
	tP, _ := s.g.sub(shareV, w0N)
	z, _ := s.g.mul(tP, x)
	vv, _ := s.g.mul(tP, w1)
	// Hand-built TT: three zero-length fields, then M, N, shareP, shareV, Z, V, w0.
	var want []byte
	want = append(want, make([]byte, 24)...)
	for _, f := range [][]byte{s.m, s.n, shareP, shareV, z, vv, w0} {
		want = binary.LittleEndian.AppendUint64(want, uint64(len(f)))
		want = append(want, f...)
	}
	if got := transcript(nil, nil, nil, s.m, s.n, shareP, shareV, z, vv, w0); !bytes.Equal(got, want) {
		t.Fatalf("transcript with empty fields:\n got %x\nwant %x", got, want)
	}
	// And the live Verifier derived its tag from exactly that transcript.
	k, _ := s.keys(want)
	if !bytes.Equal(confirmV, s.mac(k.confirmV, shareP)) {
		t.Fatal("Verifier's confirmV was not derived from the hand-built transcript")
	}
	if _, _, err := p.Finish(shareV, confirmV); err != nil {
		t.Fatal(err)
	}
}

// TestDegenerateSharesAreRejected: a peer that sends shareV = w0*N (or
// shareP = w0*M) makes Y - w0*N (X - w0*M) the identity, so Z = V = I and
// the transcript no longer depends on x, y, w1 or L. RFC 9383 §6 requires
// aborting on any received value whose cofactor multiple is the identity;
// this package also aborts when the derived point is. The identity check
// lives in the shared point parser, so a change that relaxed it for
// intermediates (for example to admit w0 = 0) would turn this red.
func TestDegenerateSharesAreRejected(t *testing.T) {
	for _, s := range Suites {
		t.Run(s.Name, func(t *testing.T) {
			w0, w1 := randomScalars(t, s)
			L, _ := s.Register(w1)
			w0N, _ := s.g.mul(s.n, w0)
			w0M, _ := s.g.mul(s.m, w0)
			p, _ := s.NewProver(nil, nil, nil, w0, w1)
			p.Start()
			// The rejection must be the identity check itself, not a later tag
			// mismatch: a peer that knows w0 can forge the tag for a degenerate TT.
			if _, _, err := p.Finish(w0N, nil); err == nil || !strings.Contains(err.Error(), "identity") {
				t.Errorf("Prover accepted shareV = w0*N: %v", err)
			}
			v, _ := s.NewVerifier(nil, nil, nil, w0, L)
			if _, _, err := v.Exchange(w0M); err == nil || !strings.Contains(err.Error(), "identity") {
				t.Errorf("Verifier accepted shareP = w0*M: %v", err)
			}
		})
	}
}
