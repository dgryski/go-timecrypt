package timecrypt

import (
	"testing"
)

func TestReference(t *testing.T) {
	var k [KEYBYTES]byte
	var in, out, out2 [BYTES]byte
	var expected = [BYTES]byte{0x5f, 0xcb, 0x87, 0xb3, 0xdc, 0x88, 0xfa, 0x85}

	for i := 0; i < KEYBYTES; i++ {
		k[i] = byte(i)
	}

	for i := 0; i < BYTES; i++ {
		in[i] = 0xff ^ byte(i)
	}

	for i := 0; i < 1000; i++ {
		Encrypt(&out, &in, &k)
		Decrypt(&out2, &out, &k)
		if out2 != in {
			t.Fatalf("roundtrip failed: iteration %d", i)
		}
		in = out
		t.Logf("%d: %x\n", i, out)
	}

	if out != expected {
		t.Errorf("final iteration check")
	}
}
