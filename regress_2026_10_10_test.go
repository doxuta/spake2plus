package spake2plus

import "testing"

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
