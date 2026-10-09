// Command spake2plus runs a SPAKE2+ (RFC 9383) exchange between an in-process
// Prover and Verifier and prints every message, so the protocol can be seen
// end to end without a network peer.
package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/doxuta/spake2plus"
)

func main() {
	var names []string
	for _, s := range spake2plus.Suites {
		names = append(names, s.Name)
	}
	suiteName := flag.String("suite", spake2plus.Suites[0].Name, "ciphersuite, one of:\n  "+strings.Join(names, "\n  "))
	password := flag.String("password", "correct horse", "password the Prover registered")
	attempt := flag.String("attempt", "", "password the Prover uses now (default: the registered one)")
	idP := flag.String("prover", "client", "idProver")
	idV := flag.String("verifier", "server", "idVerifier")
	flag.Parse()
	if *attempt == "" {
		attempt = password
	}
	var suite *spake2plus.Suite
	for _, s := range spake2plus.Suites {
		if s.Name == *suiteName {
			suite = s
		}
	}
	if suite == nil {
		fmt.Fprintf(os.Stderr, "unknown suite %q\n", *suiteName)
		os.Exit(2)
	}
	if err := demo(suite, *password, *attempt, []byte(*idP), []byte(*idV)); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// scalars derives w0 and w1 the way RFC 9383 §3.2 recommends, with PBKDF2 as
// the password hash. The RFC prefers scrypt or Argon2id; PBKDF2 is what the
// standard library has. The salt and iteration count are fixed for the demo.
func scalars(s *spake2plus.Suite, password string, idP, idV []byte) (w0, w1 []byte, err error) {
	var in []byte
	for _, f := range [][]byte{[]byte(password), idP, idV} {
		in = binary.LittleEndian.AppendUint64(in, uint64(len(f)))
		in = append(in, f...)
	}
	half := s.ScalarLen() + 8
	out, err := pbkdf2.Key(sha256.New, string(in), []byte("spake2plus demo salt"), 100_000, 2*half)
	if err != nil {
		return nil, nil, err
	}
	return s.Scalars(out[:half], out[half:])
}

func demo(s *spake2plus.Suite, password, attempt string, idP, idV []byte) error {
	ctx := []byte("spake2plus demo " + s.Name)
	fmt.Printf("suite      %s\ncontext    %q\nidProver   %q\nidVerifier %q\n\n", s.Name, ctx, idP, idV)

	// Registration: the Verifier stores (w0, L) and never sees the password or w1.
	w0, w1, err := scalars(s, password, idP, idV)
	if err != nil {
		return err
	}
	L, err := s.Register(w1)
	if err != nil {
		return err
	}
	fmt.Printf("registration record held by the Verifier\n  w0 %x\n  L  %x\n\n", w0, L)

	// Online: the Prover derives w0 and w1 from the password it has now.
	pw0, pw1, err := scalars(s, attempt, idP, idV)
	if err != nil {
		return err
	}
	prover, err := s.NewProver(ctx, idP, idV, pw0, pw1)
	if err != nil {
		return err
	}
	verifier, err := s.NewVerifier(ctx, idP, idV, w0, L)
	if err != nil {
		return err
	}
	shareP, err := prover.Start()
	if err != nil {
		return err
	}
	fmt.Printf("Prover   -> Verifier  shareP   %x\n", shareP)
	shareV, confirmV, err := verifier.Exchange(shareP)
	if err != nil {
		return err
	}
	fmt.Printf("Verifier -> Prover    shareV   %x\n", shareV)
	fmt.Printf("Verifier -> Prover    confirmV %x\n", confirmV)
	confirmP, kProver, err := prover.Finish(shareV, confirmV)
	if err != nil {
		fmt.Printf("\nProver aborts: %v\n", err)
		if attempt != password {
			fmt.Println("(the Prover used a different password than the one registered)")
		}
		return nil
	}
	fmt.Printf("Prover   -> Verifier  confirmP %x\n", confirmP)
	kVerifier, err := verifier.Finish(confirmP)
	if err != nil {
		return err
	}
	fmt.Printf("\nK_shared (Prover)   %x\nK_shared (Verifier) %x\nequal: %v\n", kProver, kVerifier, string(kProver) == string(kVerifier))
	return nil
}
