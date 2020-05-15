
// edwards25519 invert mod l

package edwards25519

// InvertModL computes z mod l and puts the result into out
func InvertModL(out, z *[32]byte) {

	var t0, t1, t2, t3, t4, t5, tz [32]byte

	copy(t1[:], z[:])        // 2^0
	squareModL(&t0, z)       // 2^1
	multModL(&t2, &t0, z)    // 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^2
		squareModL(&t0, &t0)
	}
	multModL(&t3, &t0, &t2)  // 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^3
		squareModL(&t0, &t0)
	}
	multModL(&t4, &t0, &t3)  // 2^3 + 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^4
		squareModL(&t0, &t0)
	}
	multModL(&t5, &t0, &t4) // 2^4 + 2^3 + 2^2 + 2^1 + 2^0

	copy(tz[:], t1[:])         // 2^252
	for i := 1; i < 129; i++ { // 2^128
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // tz = 252, 124
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // 2^124 + 2^122
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // 2^124 + 2^122 + 2^119 + 2^118
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // 124,122,119,118,116..113
	for i := 1; i < 7; i++ { // 2^6
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t5)  // 124,122,119,118,116..113, 111..107
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t3)  // 124,122,119,118,116..113, 111..107, 104..102
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // **124.....102**, 100..97
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95, 93
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95, 93, 89
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // **124.....102**, 100..97, 95,93,89,87..84
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t3)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62,60,59
	for i := 1; i < 8; i++ { // 2^7
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62,60,59,52
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, **100.....52**, 49,46,45
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, **100.....52**, 49,46,45,41,40
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t3)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26
	for i := 1; i < 7; i++ { // 2^6
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t3)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12
	for i := 1; i < 8; i++ { // 2^7
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t5)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2) // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0

	copy(out[:], tz[:])
}

func InvertModL_old(out, z *[32]byte) {

	// This function is not optimized

	var t0, t1, t2, t3, t4, t5, tz, zero [32]byte

	copy(t1[:], z[:])        // 2^0
	squareModL(&t0, z)       // 2^1
	multModL(&t2, &t0, z)    // 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^2
		squareModL(&t0, &t0)
	}
	multModL(&t3, &t0, &t2)  // 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^3
		squareModL(&t0, &t0)
	}
	multModL(&t4, &t0, &t3)  // 2^3 + 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^4
		squareModL(&t0, &t0)
	}
	multModL(&t5, &t0, &t4) // 2^4 + 2^3 + 2^2 + 2^1 + 2^0

	copy(tz[:], t2[:]) // tz = 2^1 + 2^0

	copy(t0[:], t1[:])
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 2^3 + 2^1 + 2^0
	copy(t0[:], t5[:])
	for i := 1; i < 6; i++ { // 2^9 + 2^8 + 2^7 + 2^6 + 2^5
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 2^9 + 2^8 + 2^7 + 2^6 + 2^5 + 2^3 + 2^1 + 2^0
	copy(t0[:], t1[:])
	for i := 1; i < 13; i++ { // 2^12
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 2^12 + 2^9 + 2^8 + 2^7 + 2^6 + 2^5 + 2^3 + 2^1 + 2^0
	copy(t0[:], t3[:])
	for i := 1; i < 15; i++ { // 2^16 + 2^15 + 2^14
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 19; i++ { // 2^18
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t4[:])
	for i := 1; i < 21; i++ { // 2^23 + 2^22 + 2^21 + 2^20
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t3[:])
	for i := 1; i < 27; i++ { // 2^28 + 2^27 + 2^26
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 31; i++ { // 2^30
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 34; i++ { // 2^33
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 36; i++ { // 2^36 + 2^35
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 41; i++ { // 2^41 + 2^40
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 46; i++ { // 2^46 + 2^45
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 50; i++ { // 2^49
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 53; i++ { // 2^52
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 60; i++ { // 2^60 + 2^59
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 63; i++ { // 2^62
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 62,60,59,52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 66; i++ { // 2^66 + 2^65
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 69; i++ { // 2^68
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 71; i++ { // 2^71 + 2^70
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t3[:])
	for i := 1; i < 75; i++ { // 2^76 + 2^75 + 2^74
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 80; i++ { // 2^82 + 2^81 + 2^80 + 2^79
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 85; i++ { // 2^87 + 2^86 + 2^85 + 2^84
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 90; i++ { // 2^89
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 94; i++ { // 2^93
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 96; i++ { // 2^95
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 95,93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 98; i++ { // 2^100 + 2^99 + 2^98 + 2^97
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 100..97, 95,93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t3[:])
	for i := 1; i < 103; i++ { // 2^104 + 2^103 + 2^102
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 104..102, **100.....52**, **49.....0**
	copy(t0[:], t5[:])
	for i := 1; i < 108; i++ { // 2^111 + 2^110 + 2^109 + 2^108 + 2^107
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 114; i++ { // 2^116 + 2^115 + 2^114 + 2^113
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 119; i++ { // 2^119 + 2^118
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 123; i++ { // 2^122
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 122,119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 125; i++ { // 2^124
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 124,122,119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], z[:])
	for i := 1; i < 253; i++ { // 2^252
		ScMulAdd(&t0, &t0, &t0, &zero)
	}
	multModL(&tz, &t0, &tz) // tz = 252, 124......

	copy(out[:], tz[:])
}

func squareModL(out, z *[32]byte) {
	// we keep the old commands for benchmarking
	// var zero [32]byte
	// ScMulAdd(out, z, z, &zero)
	ScMul(out, z, z)
}

func multModL(out, z, w *[32]byte) {
	// we keep the old commands for benchmarking
	// var zero [32]byte
	// ScMulAdd(out, z, w, &zero)
	ScMul(out, z, w)
}

// The scalars are GF(2^252 + 27742317777372353535851937790883648493).
// Input:
//   a[0]+256*a[1]+...+256^31*a[31] = a
//   b[0]+256*b[1]+...+256^31*b[31] = b
//
// Output:
//   s[0]+256*s[1]+...+256^31*s[31] = (ab) mod l
//   where l = 2^252 + 27742317777372353535851937790883648493.
func ScMul(s, a, b *[32]byte) {
	a0 := 2097151 & load3(a[:])
	a1 := 2097151 & (load4(a[2:]) >> 5)
	a2 := 2097151 & (load3(a[5:]) >> 2)
	a3 := 2097151 & (load4(a[7:]) >> 7)
	a4 := 2097151 & (load4(a[10:]) >> 4)
	a5 := 2097151 & (load3(a[13:]) >> 1)
	a6 := 2097151 & (load4(a[15:]) >> 6)
	a7 := 2097151 & (load3(a[18:]) >> 3)
	a8 := 2097151 & load3(a[21:])
	a9 := 2097151 & (load4(a[23:]) >> 5)
	a10 := 2097151 & (load3(a[26:]) >> 2)
	a11 := (load4(a[28:]) >> 7)
	b0 := 2097151 & load3(b[:])
	b1 := 2097151 & (load4(b[2:]) >> 5)
	b2 := 2097151 & (load3(b[5:]) >> 2)
	b3 := 2097151 & (load4(b[7:]) >> 7)
	b4 := 2097151 & (load4(b[10:]) >> 4)
	b5 := 2097151 & (load3(b[13:]) >> 1)
	b6 := 2097151 & (load4(b[15:]) >> 6)
	b7 := 2097151 & (load3(b[18:]) >> 3)
	b8 := 2097151 & load3(b[21:])
	b9 := 2097151 & (load4(b[23:]) >> 5)
	b10 := 2097151 & (load3(b[26:]) >> 2)
	b11 := (load4(b[28:]) >> 7)
	var carry [23]int64

	s0 := a0 * b0
	s1 := a0*b1 + a1*b0
	s2 := a0*b2 + a1*b1 + a2*b0
	s3 := a0*b3 + a1*b2 + a2*b1 + a3*b0
	s4 := a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
	s5 := a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0
	s6 := a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0
	s7 := a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0
	s8 := a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0
	s9 := a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0
	s10 := a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0
	s11 := a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0
	s12 := a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1
	s13 := a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2
	s14 := a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3
	s15 := a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4
	s16 := a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5
	s17 := a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6
	s18 := a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7
	s19 := a8*b11 + a9*b10 + a10*b9 + a11*b8
	s20 := a9*b11 + a10*b10 + a11*b9
	s21 := a10*b11 + a11*b10
	s22 := a11 * b11
	s23 := int64(0)

	carry[0] = (s0 + (1 << 20)) >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[2] = (s2 + (1 << 20)) >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[4] = (s4 + (1 << 20)) >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[6] = (s6 + (1 << 20)) >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[8] = (s8 + (1 << 20)) >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[10] = (s10 + (1 << 20)) >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21
	carry[12] = (s12 + (1 << 20)) >> 21
	s13 += carry[12]
	s12 -= carry[12] << 21
	carry[14] = (s14 + (1 << 20)) >> 21
	s15 += carry[14]
	s14 -= carry[14] << 21
	carry[16] = (s16 + (1 << 20)) >> 21
	s17 += carry[16]
	s16 -= carry[16] << 21
	carry[18] = (s18 + (1 << 20)) >> 21
	s19 += carry[18]
	s18 -= carry[18] << 21
	carry[20] = (s20 + (1 << 20)) >> 21
	s21 += carry[20]
	s20 -= carry[20] << 21
	carry[22] = (s22 + (1 << 20)) >> 21
	s23 += carry[22]
	s22 -= carry[22] << 21

	carry[1] = (s1 + (1 << 20)) >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[3] = (s3 + (1 << 20)) >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[5] = (s5 + (1 << 20)) >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[7] = (s7 + (1 << 20)) >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[9] = (s9 + (1 << 20)) >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[11] = (s11 + (1 << 20)) >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21
	carry[13] = (s13 + (1 << 20)) >> 21
	s14 += carry[13]
	s13 -= carry[13] << 21
	carry[15] = (s15 + (1 << 20)) >> 21
	s16 += carry[15]
	s15 -= carry[15] << 21
	carry[17] = (s17 + (1 << 20)) >> 21
	s18 += carry[17]
	s17 -= carry[17] << 21
	carry[19] = (s19 + (1 << 20)) >> 21
	s20 += carry[19]
	s19 -= carry[19] << 21
	carry[21] = (s21 + (1 << 20)) >> 21
	s22 += carry[21]
	s21 -= carry[21] << 21

	s11 += s23 * 666643
	s12 += s23 * 470296
	s13 += s23 * 654183
	s14 -= s23 * 997805
	s15 += s23 * 136657
	s16 -= s23 * 683901
	s23 = 0

	s10 += s22 * 666643
	s11 += s22 * 470296
	s12 += s22 * 654183
	s13 -= s22 * 997805
	s14 += s22 * 136657
	s15 -= s22 * 683901
	s22 = 0

	s9 += s21 * 666643
	s10 += s21 * 470296
	s11 += s21 * 654183
	s12 -= s21 * 997805
	s13 += s21 * 136657
	s14 -= s21 * 683901
	s21 = 0

	s8 += s20 * 666643
	s9 += s20 * 470296
	s10 += s20 * 654183
	s11 -= s20 * 997805
	s12 += s20 * 136657
	s13 -= s20 * 683901
	s20 = 0

	s7 += s19 * 666643
	s8 += s19 * 470296
	s9 += s19 * 654183
	s10 -= s19 * 997805
	s11 += s19 * 136657
	s12 -= s19 * 683901
	s19 = 0

	s6 += s18 * 666643
	s7 += s18 * 470296
	s8 += s18 * 654183
	s9 -= s18 * 997805
	s10 += s18 * 136657
	s11 -= s18 * 683901
	s18 = 0

	carry[6] = (s6 + (1 << 20)) >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[8] = (s8 + (1 << 20)) >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[10] = (s10 + (1 << 20)) >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21
	carry[12] = (s12 + (1 << 20)) >> 21
	s13 += carry[12]
	s12 -= carry[12] << 21
	carry[14] = (s14 + (1 << 20)) >> 21
	s15 += carry[14]
	s14 -= carry[14] << 21
	carry[16] = (s16 + (1 << 20)) >> 21
	s17 += carry[16]
	s16 -= carry[16] << 21

	carry[7] = (s7 + (1 << 20)) >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[9] = (s9 + (1 << 20)) >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[11] = (s11 + (1 << 20)) >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21
	carry[13] = (s13 + (1 << 20)) >> 21
	s14 += carry[13]
	s13 -= carry[13] << 21
	carry[15] = (s15 + (1 << 20)) >> 21
	s16 += carry[15]
	s15 -= carry[15] << 21

	s5 += s17 * 666643
	s6 += s17 * 470296
	s7 += s17 * 654183
	s8 -= s17 * 997805
	s9 += s17 * 136657
	s10 -= s17 * 683901
	s17 = 0

	s4 += s16 * 666643
	s5 += s16 * 470296
	s6 += s16 * 654183
	s7 -= s16 * 997805
	s8 += s16 * 136657
	s9 -= s16 * 683901
	s16 = 0

	s3 += s15 * 666643
	s4 += s15 * 470296
	s5 += s15 * 654183
	s6 -= s15 * 997805
	s7 += s15 * 136657
	s8 -= s15 * 683901
	s15 = 0

	s2 += s14 * 666643
	s3 += s14 * 470296
	s4 += s14 * 654183
	s5 -= s14 * 997805
	s6 += s14 * 136657
	s7 -= s14 * 683901
	s14 = 0

	s1 += s13 * 666643
	s2 += s13 * 470296
	s3 += s13 * 654183
	s4 -= s13 * 997805
	s5 += s13 * 136657
	s6 -= s13 * 683901
	s13 = 0

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry[0] = (s0 + (1 << 20)) >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[2] = (s2 + (1 << 20)) >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[4] = (s4 + (1 << 20)) >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[6] = (s6 + (1 << 20)) >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[8] = (s8 + (1 << 20)) >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[10] = (s10 + (1 << 20)) >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21

	carry[1] = (s1 + (1 << 20)) >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[3] = (s3 + (1 << 20)) >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[5] = (s5 + (1 << 20)) >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[7] = (s7 + (1 << 20)) >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[9] = (s9 + (1 << 20)) >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[11] = (s11 + (1 << 20)) >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry[0] = s0 >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[1] = s1 >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[2] = s2 >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[3] = s3 >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[4] = s4 >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[5] = s5 >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[6] = s6 >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[7] = s7 >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[8] = s8 >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[9] = s9 >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[10] = s10 >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21
	carry[11] = s11 >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry[0] = s0 >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[1] = s1 >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[2] = s2 >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[3] = s3 >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[4] = s4 >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[5] = s5 >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[6] = s6 >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[7] = s7 >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[8] = s8 >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[9] = s9 >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[10] = s10 >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21

	s[0] = byte(s0 >> 0)
	s[1] = byte(s0 >> 8)
	s[2] = byte((s0 >> 16) | (s1 << 5))
	s[3] = byte(s1 >> 3)
	s[4] = byte(s1 >> 11)
	s[5] = byte((s1 >> 19) | (s2 << 2))
	s[6] = byte(s2 >> 6)
	s[7] = byte((s2 >> 14) | (s3 << 7))
	s[8] = byte(s3 >> 1)
	s[9] = byte(s3 >> 9)
	s[10] = byte((s3 >> 17) | (s4 << 4))
	s[11] = byte(s4 >> 4)
	s[12] = byte(s4 >> 12)
	s[13] = byte((s4 >> 20) | (s5 << 1))
	s[14] = byte(s5 >> 7)
	s[15] = byte((s5 >> 15) | (s6 << 6))
	s[16] = byte(s6 >> 2)
	s[17] = byte(s6 >> 10)
	s[18] = byte((s6 >> 18) | (s7 << 3))
	s[19] = byte(s7 >> 5)
	s[20] = byte(s7 >> 13)
	s[21] = byte(s8 >> 0)
	s[22] = byte(s8 >> 8)
	s[23] = byte((s8 >> 16) | (s9 << 5))
	s[24] = byte(s9 >> 3)
	s[25] = byte(s9 >> 11)
	s[26] = byte((s9 >> 19) | (s10 << 2))
	s[27] = byte(s10 >> 6)
	s[28] = byte((s10 >> 14) | (s11 << 7))
	s[29] = byte(s11 >> 1)
	s[30] = byte(s11 >> 9)
	s[31] = byte(s11 >> 17)
}

// GeScalarMultVartime sets r = a*A
// where a = a[0]+256*a[1]+...+256^31 a[31].
// and A is a point on the curve
func GeScalarMultVartime(r *ProjectiveGroupElement, a *[32]byte, A *ExtendedGroupElement) {
	var aSlide [256]int8
	var Ai [8]CachedGroupElement // A,3A,5A,7A,9A,11A,13A,15A
	var t CompletedGroupElement
	var u, A2 ExtendedGroupElement
	var i int

	slide(&aSlide, a)

	A.ToCached(&Ai[0])
	A.Double(&t)
	t.ToExtended(&A2)

	for i := 0; i < 7; i++ {
		geAdd(&t, &A2, &Ai[i])
		t.ToExtended(&u)
		u.ToCached(&Ai[i+1])
	}

	r.Zero()

	for i = 255; i >= 0; i-- {
		if aSlide[i] != 0 {
			break
		}
	}

	for ; i >= 0; i-- {
		r.Double(&t)

		if aSlide[i] > 0 {
			t.ToExtended(&u)
			geAdd(&t, &u, &Ai[aSlide[i]/2])
		} else if aSlide[i] < 0 {
			t.ToExtended(&u)
			geSub(&t, &u, &Ai[(-aSlide[i])/2])
		}

		t.ToProjective(r)
	}
}

func (p *ProjectiveGroupElement) ToExtended(r *ExtendedGroupElement) {
	var recip, t FieldElement

	FeInvert(&recip, &p.Z)
	FeMul(&t, &p.X, &p.Y)

	FeCopy(&r.X, &p.X)
	FeCopy(&r.Y, &p.Y)
	FeCopy(&r.Z, &p.Z)
	FeMul(&r.T, &t, &recip)
}

func (p *ProjectiveGroupElement) ProjBytesExt(r *ExtendedGroupElement) {
	var buff [32]byte
	p.ToBytes(&buff)
	r.FromBytes(&buff)
	// I AM FAILING TO ASSERT FromBytes()

	//var A2 edwards25519.ExtendedGroupElement
	//if ok := r.FromBytes(&buff); !ok {
	//	return nil, errors.New("failed to create an extended group element A2 from A")
	//}
}
