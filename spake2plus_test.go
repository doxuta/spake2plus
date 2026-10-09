package spake2plus

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// run performs a full exchange and returns both shared keys and the first error.
func run(s *Suite, ctx, idP, idV, w0, w1, w0v, L []byte) (kp, kv []byte, err error) {
	p, err := s.NewProver(ctx, idP, idV, w0, w1)
	if err != nil {
		return nil, nil, err
	}
	v, err := s.NewVerifier(ctx, idP, idV, w0v, L)
	if err != nil {
		return nil, nil, err
	}
	shareP, err := p.Start()
	if err != nil {
		return nil, nil, err
	}
	shareV, confirmV, err := v.Exchange(shareP)
	if err != nil {
		return nil, nil, err
	}
	confirmP, kp, err := p.Finish(shareV, confirmV)
	if err != nil {
		return nil, nil, err
	}
	kv, err = v.Finish(confirmP)
	return kp, kv, err
}

func randomScalars(t *testing.T, s *Suite) (w0, w1 []byte) {
	t.Helper()
	buf := make([]byte, 2*(s.ScalarLen()+8))
	rand.Read(buf)
	w0, w1, err := s.Scalars(buf[:len(buf)/2], buf[len(buf)/2:])
	if err != nil {
		t.Fatal(err)
	}
	return w0, w1
}

func TestRoundTripEverySuite(t *testing.T) {
	for _, s := range Suites {
		t.Run(s.Name, func(t *testing.T) {
			w0, w1 := randomScalars(t, s)
			L, err := s.Register(w1)
			if err != nil {
				t.Fatal(err)
			}
			kp, kv, err := run(s, []byte("test"), []byte("client"), []byte("server"), w0, w1, w0, L)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(kp, kv) || len(kp) != s.hash().Size() {
				t.Fatalf("shared keys differ or wrong length: %x / %x", kp, kv)
			}
			// Two runs never agree on x, so the key is fresh each time.
			kp2, _, err := run(s, []byte("test"), []byte("client"), []byte("server"), w0, w1, w0, L)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(kp, kp2) {
				t.Fatal("two runs produced the same K_shared")
			}
		})
	}
}

func TestWrongPasswordFails(t *testing.T) {
	s := P256SHA256HKDFHMAC
	w0, w1 := randomScalars(t, s)
	L, _ := s.Register(w1)
	bad0, bad1 := randomScalars(t, s)
	badL, _ := s.Register(bad1)
	ctx, idP, idV := []byte("ctx"), []byte("client"), []byte("server")
	// V enters the transcript on both sides, so any mismatch in w0, w1 or L
	// changes K_confirmV and the Prover rejects confirmV before it ever sends
	// confirmP. confirmP only fails on its own when it is tampered with.
	for name, tc := range map[string]struct{ w0, w1, w0v, L []byte }{
		"prover has wrong w0":     {bad0, w1, w0, L},
		"prover has wrong w1":     {w0, bad1, w0, L},
		"verifier holds wrong L":  {w0, w1, w0, badL},
		"verifier holds wrong w0": {w0, w1, bad0, L},
		"everything wrong":        {bad0, bad1, w0, L},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := run(s, ctx, idP, idV, tc.w0, tc.w1, tc.w0v, tc.L)
			if err == nil || !strings.Contains(err.Error(), "confirmV does not verify") {
				t.Fatalf("got %v, want confirmV rejection", err)
			}
		})
	}
}

func TestTamperedTagsFail(t *testing.T) {
	s := P256SHA256HKDFHMAC
	w0, w1 := randomScalars(t, s)
	L, _ := s.Register(w1)
	p, _ := s.NewProver(nil, nil, nil, w0, w1)
	v, _ := s.NewVerifier(nil, nil, nil, w0, L)
	shareP, _ := p.Start()
	shareV, confirmV, _ := v.Exchange(shareP)
	flipped := bytes.Clone(confirmV)
	flipped[0] ^= 1
	if _, _, err := p.Finish(shareV, flipped); err == nil {
		t.Fatal("tampered confirmV accepted")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"flipped": func(b []byte) []byte { c := bytes.Clone(b); c[0] ^= 1; return c },
		"short":   func(b []byte) []byte { return b[:len(b)-1] },
		"empty":   func([]byte) []byte { return nil },
	} {
		p, _ := s.NewProver(nil, nil, nil, w0, w1)
		v, _ := s.NewVerifier(nil, nil, nil, w0, L)
		shareP, _ := p.Start()
		shareV, confirmV, _ := v.Exchange(shareP)
		confirmP, _, err := p.Finish(shareV, confirmV)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Finish(mutate(confirmP)); err == nil || !strings.Contains(err.Error(), "confirmP does not verify") {
			t.Errorf("%s confirmP: got %v", name, err)
		}
	}
}

func TestContextAndIdentitiesBindTheKey(t *testing.T) {
	s := P256SHA256HKDFHMAC
	w0, w1 := randomScalars(t, s)
	L, _ := s.Register(w1)
	p, _ := s.NewProver([]byte("app/1"), []byte("client"), []byte("server"), w0, w1)
	v, _ := s.NewVerifier([]byte("app/2"), []byte("client"), []byte("server"), w0, L)
	shareP, _ := p.Start()
	shareV, confirmV, _ := v.Exchange(shareP)
	if _, _, err := p.Finish(shareV, confirmV); err == nil {
		t.Fatal("different contexts produced a verifying confirmV")
	}
	p, _ = s.NewProver(nil, []byte("client"), []byte("server"), w0, w1)
	v, _ = s.NewVerifier(nil, []byte("client"), []byte("other"), w0, L)
	shareP, _ = p.Start()
	shareV, confirmV, _ = v.Exchange(shareP)
	if _, _, err := p.Finish(shareV, confirmV); err == nil {
		t.Fatal("different identities produced a verifying confirmV")
	}
}

func TestRejectsBadGroupElements(t *testing.T) {
	s := P256SHA256HKDFHMAC
	w0, w1 := randomScalars(t, s)
	L, _ := s.Register(w1)
	valid, _ := s.Register(w0)
	offCurve := bytes.Clone(valid)
	offCurve[len(offCurve)-1] ^= 1
	for name, bad := range map[string][]byte{
		"identity":   {0x00},
		"empty":      {},
		"truncated":  valid[:33],
		"off-curve":  offCurve,
		"compressed": valid[:33:33], // 0x04 prefix with one coordinate
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.NewVerifier(nil, nil, nil, w0, bad); err == nil {
				t.Error("NewVerifier accepted a bad L")
			}
			v, _ := s.NewVerifier(nil, nil, nil, w0, L)
			if _, _, err := v.Exchange(bad); err == nil {
				t.Error("Exchange accepted a bad shareP")
			}
			p, _ := s.NewProver(nil, nil, nil, w0, w1)
			p.Start()
			if _, _, err := p.Finish(bad, nil); err == nil {
				t.Error("Finish accepted a bad shareV")
			}
		})
	}
}

func TestRejectsBadScalars(t *testing.T) {
	s := P256SHA256HKDFHMAC
	w0, w1 := randomScalars(t, s)
	short := w0[:31]
	order := s.g.order.FillBytes(make([]byte, 32))
	for name, bad := range map[string][]byte{"short": short, "long": append(bytes.Clone(w0), 0), "order": order} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Register(bad); err == nil {
				t.Error("Register accepted w1")
			}
			if _, err := s.NewProver(nil, nil, nil, bad, w1); err == nil {
				t.Error("NewProver accepted w0")
			}
			if _, err := s.NewProver(nil, nil, nil, w0, bad); err == nil {
				t.Error("NewProver accepted w1")
			}
			if _, err := s.NewVerifier(nil, nil, nil, bad, nil); err == nil {
				t.Error("NewVerifier accepted w0")
			}
		})
	}
	if _, _, err := s.Scalars(make([]byte, 39), make([]byte, 40)); err == nil {
		t.Error("Scalars accepted a 39-byte half")
	}
	a, b, err := s.Scalars(bytes.Repeat([]byte{0xff}, 40), make([]byte, 40))
	if err != nil || len(a) != 32 || len(b) != 32 || s.g.checkScalar("a", a) != nil {
		t.Errorf("Scalars did not reduce: %x %x %v", a, b, err)
	}
}

func TestStateMachine(t *testing.T) {
	s := P256SHA256HKDFHMAC
	w0, w1 := randomScalars(t, s)
	L, _ := s.Register(w1)
	p, _ := s.NewProver(nil, nil, nil, w0, w1)
	v, _ := s.NewVerifier(nil, nil, nil, w0, L)
	if _, _, err := p.Finish(nil, nil); err == nil {
		t.Error("Finish before Start")
	}
	if _, err := v.Finish(nil); err == nil {
		t.Error("Finish before Exchange")
	}
	shareP, _ := p.Start()
	if _, err := p.Start(); err == nil {
		t.Error("Start twice")
	}
	shareV, confirmV, _ := v.Exchange(shareP)
	if _, _, err := v.Exchange(shareP); err == nil {
		t.Error("Exchange twice")
	}
	confirmP, _, err := p.Finish(shareV, confirmV)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Finish(shareV, confirmV); err == nil {
		t.Error("Finish twice")
	}
	if _, err := v.Finish(confirmP); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Finish(confirmP); err == nil {
		t.Error("Finish twice")
	}
}
