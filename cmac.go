package spake2plus

import "crypto/aes"

// cmacAES is AES-CMAC (RFC 4493) for the two CMAC-AES-128 suites. The
// standard library has no CMAC, and the algorithm is thirty lines.
func cmacAES(key, msg []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // keys come from HKDF and are always 16 bytes
	}
	const bs = aes.BlockSize
	k1 := make([]byte, bs)
	c.Encrypt(k1, k1)
	k1 = shiftXor(k1)
	k2 := shiftXor(k1)

	n := (len(msg) + bs - 1) / bs
	last := make([]byte, bs)
	if n == 0 || len(msg)%bs != 0 {
		// Incomplete final block: pad with 10* and use K2.
		if n == 0 {
			n = 1
		}
		copy(last, msg[(n-1)*bs:])
		last[len(msg)-(n-1)*bs] = 0x80
		for i := range last {
			last[i] ^= k2[i]
		}
	} else {
		for i := range last {
			last[i] = msg[(n-1)*bs+i] ^ k1[i]
		}
	}
	x := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		for j := range x {
			x[j] ^= msg[i*bs+j]
		}
		c.Encrypt(x, x)
	}
	for j := range x {
		x[j] ^= last[j]
	}
	c.Encrypt(x, x)
	return x
}

// shiftXor returns b<<1, xored with Rb=0x87 when the top bit was set
// (RFC 4493 §2.3). Returns a new slice.
func shiftXor(b []byte) []byte {
	out := make([]byte, len(b))
	var carry byte
	for i := len(b) - 1; i >= 0; i-- {
		out[i] = b[i]<<1 | carry
		carry = b[i] >> 7
	}
	if carry == 1 {
		out[len(out)-1] ^= 0x87
	}
	return out
}
