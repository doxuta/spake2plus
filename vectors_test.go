package spake2plus

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// vectorSet is one "[Context=...]" block of RFC 9383 Appendix C, parsed
// verbatim from the RFC text in testdata/.
type vectorSet struct {
	context, idProver, idVerifier string
	values                        map[string][]byte // "w0", "shareP", "HMAC(K_confirmP, shareV)", ...
	raw                           map[string]string // hex text as printed, joined across lines
}

func loadVectors(t *testing.T) []vectorSet {
	t.Helper()
	f, err := os.Open("testdata/rfc9383-appendix-c.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var sets []vectorSet
	var cur *vectorSet
	var key string      // value currently being continued
	var bracket *string // [Context=b'...'] currently being continued
	flushKey := func() { key = "" }
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if bracket != nil { // continuation of a bracketed identity/context
			*bracket += strings.TrimSuffix(line, "']")
			if strings.HasSuffix(line, "']") {
				bracket = nil
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			flushKey()
			name, rest, _ := strings.Cut(strings.TrimPrefix(line, "["), "=b'")
			var dst *string
			switch name {
			case "Context":
				sets = append(sets, vectorSet{values: map[string][]byte{}, raw: map[string]string{}})
				cur = &sets[len(sets)-1]
				dst = &cur.context
			case "idProver":
				dst = &cur.idProver
			case "idVerifier":
				dst = &cur.idVerifier
			default:
				t.Fatalf("unknown bracket %q", name)
			}
			*dst = strings.TrimSuffix(rest, "']")
			if !strings.HasSuffix(rest, "']") {
				bracket = dst
			}
			continue
		}
		if name, rest, ok := strings.Cut(line, " = 0x"); ok {
			key = name
			cur.raw[key] = rest
			continue
		}
		if key != "" { // continuation of a hex value
			cur.raw[key] += line
			continue
		}
		t.Fatalf("unparsed line %q", line)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for _, vs := range sets {
		for k, h := range vs.raw { // lines break mid-byte, so decode only the joined text
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Fatalf("%s %s: %v", vs.context, k, err)
			}
			vs.values[k] = b
		}
	}
	return sets
}

func suiteFor(t *testing.T, context string) *Suite {
	t.Helper()
	name := strings.TrimSuffix(strings.TrimPrefix(context, "SPAKE2+-"), " Test Vectors")
	for _, s := range Suites {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no suite for context %q", context)
	return nil
}

func TestRFC9383Vectors(t *testing.T) {
	sets := loadVectors(t)
	if len(sets) != 7 {
		t.Fatalf("parsed %d vector sets, RFC 9383 Appendix C has 7", len(sets))
	}
	for _, vs := range sets {
		s := suiteFor(t, vs.context)
		t.Run(s.Name, func(t *testing.T) {
			v := vs.values
			if len(v) != 16 {
				t.Fatalf("parsed %d values, want 16", len(v))
			}
			ctx, idP, idV := []byte(vs.context), []byte(vs.idProver), []byte(vs.idVerifier)
			want := func(name string, got []byte) {
				t.Helper()
				if !bytes.Equal(got, v[name]) {
					t.Errorf("%s:\n got %x\nwant %x", name, got, v[name])
				}
			}

			L, err := s.Register(v["w1"])
			if err != nil {
				t.Fatal(err)
			}
			want("L", L)

			p, err := s.NewProver(ctx, idP, idV, v["w0"], v["w1"])
			if err != nil {
				t.Fatal(err)
			}
			shareP, err := p.start(v["x"])
			if err != nil {
				t.Fatal(err)
			}
			want("shareP", shareP)

			vf, err := s.NewVerifier(ctx, idP, idV, v["w0"], v["L"])
			if err != nil {
				t.Fatal(err)
			}
			shareV, confirmV, err := vf.exchange(v["shareP"], v["y"])
			if err != nil {
				t.Fatal(err)
			}
			want("shareV", shareV)

			// Intermediates, Prover side: Z = x*(Y - w0*N), V = w1*(Y - w0*N).
			w0N, _ := s.g.mul(s.n, v["w0"])
			tP, _ := s.g.sub(v["shareV"], w0N)
			z, _ := s.g.mul(tP, v["x"])
			vv, _ := s.g.mul(tP, v["w1"])
			want("Z", z)
			want("V", vv)
			// Verifier side: Z = y*(X - w0*M), V = y*L.
			w0M, _ := s.g.mul(s.m, v["w0"])
			tV, _ := s.g.sub(v["shareP"], w0M)
			z2, _ := s.g.mul(tV, v["y"])
			v2, _ := s.g.mul(v["L"], v["y"])
			want("Z", z2)
			want("V", v2)

			tt := transcript(ctx, idP, idV, s.m, s.n, v["shareP"], v["shareV"], v["Z"], v["V"], v["w0"])
			want("TT", tt)
			h := s.hash()
			h.Write(tt)
			want("K_main", h.Sum(nil))
			k, err := s.keys(tt)
			if err != nil {
				t.Fatal(err)
			}
			want("K_confirmP", k.confirmP)
			want("K_confirmV", k.confirmV)
			want("K_shared", k.shared)
			macName := "HMAC"
			if s.cmac {
				macName = "CMAC"
			}
			want(macName+"(K_confirmV, shareP)", confirmV)

			// The full public flow ends with the RFC's tags and K_shared on both sides.
			confirmP, sharedP, err := p.Finish(shareV, confirmV)
			if err != nil {
				t.Fatal(err)
			}
			want(macName+"(K_confirmP, shareV)", confirmP)
			want("K_shared", sharedP)
			sharedV, err := vf.Finish(confirmP)
			if err != nil {
				t.Fatal(err)
			}
			want("K_shared", sharedV)
		})
	}
}

// TestVectorParserSeesEveryField guards the parser itself: a silently dropped
// field would make the test above vacuous for that field.
func TestVectorParserSeesEveryField(t *testing.T) {
	for _, vs := range loadVectors(t) {
		for _, name := range []string{"w0", "w1", "L", "x", "shareP", "y", "shareV", "Z", "V", "TT", "K_main", "K_confirmP", "K_confirmV", "K_shared"} {
			if len(vs.values[name]) == 0 {
				t.Errorf("%s: missing %s", vs.context, name)
			}
		}
		if vs.idProver != "client" || vs.idVerifier != "server" {
			t.Errorf("%s: identities %q/%q", vs.context, vs.idProver, vs.idVerifier)
		}
		if strings.Contains(vs.context, "\n") || !strings.HasSuffix(vs.context, " Test Vectors") {
			t.Errorf("context joined badly: %q", vs.context)
		}
	}
}

func TestCMACRFC4493(t *testing.T) {
	key := unhex("2b7e151628aed2a6abf7158809cf4f3c")
	msg := unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	for _, tc := range []struct {
		n    int
		want string
	}{
		{0, "bb1d6929e95937287fa37d129b756746"},
		{16, "070a16b46b4d4144f79bdd9dd04a287c"},
		{40, "dfa66747de9ae63030ca32611497c827"},
		{64, "51f0bebf7e3b9d92fc49741779363cfe"},
	} {
		if got := hex.EncodeToString(cmacAES(key, msg[:tc.n])); got != tc.want {
			t.Errorf("len %d: got %s want %s", tc.n, got, tc.want)
		}
	}
}
