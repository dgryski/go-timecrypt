package timecrypt

import "encoding/binary"

func rotl(x uint16, r uint) uint16 {
	return (x << r) | (x >> (16 - r))
}

func fwd(state *[4]uint16) {
	state[0] += state[1]
	state[2] += state[3]
	state[1] = rotl(state[1], 3)
	state[3] = rotl(state[3], 10)
	state[1] ^= state[0]
	state[3] ^= state[2]
	state[0] = rotl(state[0], 8)
	state[0] += state[3]
	state[2] += state[1]
	state[1] = rotl(state[1], 9)
	state[3] = rotl(state[3], 14)
	state[1] ^= state[2]
	state[3] ^= state[0]
	state[2] = rotl(state[2], 8)
}

func bwd(state *[4]uint16) {
	state[2] = rotl(state[2], 8)
	state[1] ^= state[2]
	state[3] ^= state[0]
	state[1] = rotl(state[1], 7)
	state[3] = rotl(state[3], 2)
	state[0] -= state[3]
	state[2] -= state[1]
	state[0] = rotl(state[0], 8)
	state[1] ^= state[0]
	state[3] ^= state[2]
	state[1] = rotl(state[1], 13)
	state[3] = rotl(state[3], 6)
	state[0] -= state[1]
	state[2] -= state[3]
}

func xor4(out, x, y *[4]uint16) {
	out[0] = x[0] ^ y[0]
	out[1] = x[1] ^ y[1]
	out[2] = x[2] ^ y[2]
	out[3] = x[3] ^ y[3]
}

const (
	BYTES    = 8
	KEYBYTES = 16
)

func Encrypt(out, in *[BYTES]byte, key *[KEYBYTES]byte) {
	var state [4]uint16

	key1 := [4]uint16{
		binary.LittleEndian.Uint16(key[0:2]),
		binary.LittleEndian.Uint16(key[2:4]),
		binary.LittleEndian.Uint16(key[4:6]),
		binary.LittleEndian.Uint16(key[6:8]),
	}
	key2 := [4]uint16{
		binary.LittleEndian.Uint16(key[8:10]),
		binary.LittleEndian.Uint16(key[10:12]),
		binary.LittleEndian.Uint16(key[12:14]),
		binary.LittleEndian.Uint16(key[14:16]),
	}

	in16 := [4]uint16{
		binary.LittleEndian.Uint16(in[0:2]),
		binary.LittleEndian.Uint16(in[2:4]),
		binary.LittleEndian.Uint16(in[4:6]),
		binary.LittleEndian.Uint16(in[6:8]),
	}

	xor4(&state, &in16, &key1)
	fwd(&state)
	xor4(&state, &state, &key2)
	fwd(&state)
	xor4(&state, &state, &key1)
	fwd(&state)
	var out16 [4]uint16
	xor4(&out16, &state, &key2)

	binary.LittleEndian.PutUint16(out[0:2], out16[0])
	binary.LittleEndian.PutUint16(out[2:4], out16[1])
	binary.LittleEndian.PutUint16(out[4:6], out16[2])
	binary.LittleEndian.PutUint16(out[6:8], out16[3])

}

func Decrypt(out, in *[BYTES]byte, key *[KEYBYTES]byte) {
	var state [4]uint16

	key1 := [4]uint16{
		binary.LittleEndian.Uint16(key[0:2]),
		binary.LittleEndian.Uint16(key[2:4]),
		binary.LittleEndian.Uint16(key[4:6]),
		binary.LittleEndian.Uint16(key[6:8]),
	}
	key2 := [4]uint16{
		binary.LittleEndian.Uint16(key[8:10]),
		binary.LittleEndian.Uint16(key[10:12]),
		binary.LittleEndian.Uint16(key[12:14]),
		binary.LittleEndian.Uint16(key[14:16]),
	}

	in16 := [4]uint16{
		binary.LittleEndian.Uint16(in[0:2]),
		binary.LittleEndian.Uint16(in[2:4]),
		binary.LittleEndian.Uint16(in[4:6]),
		binary.LittleEndian.Uint16(in[6:8]),
	}

	xor4(&state, &in16, &key2)
	bwd(&state)
	xor4(&state, &state, &key1)
	bwd(&state)
	xor4(&state, &state, &key2)
	bwd(&state)

	var out16 [4]uint16
	xor4(&out16, &state, &key1)

	binary.LittleEndian.PutUint16(out[0:2], out16[0])
	binary.LittleEndian.PutUint16(out[2:4], out16[1])
	binary.LittleEndian.PutUint16(out[4:6], out16[2])
	binary.LittleEndian.PutUint16(out[6:8], out16[3])
}
