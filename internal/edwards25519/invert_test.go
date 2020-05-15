
// edwards25519 invert mod l unit tests

package edwards25519

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

// test vectors
const INV_2 = "3618502788666131106986593281521497120428558179689953803000975469142727125495"
const INV_17 = "851412420862619083996845478005058145983190159927047953647288345680641676587"

func TestScMul(t *testing.T) {

	var s, s1, zero [32]byte
	a := rnd32Bytes(t)
	b := rnd32Bytes(t)

	ScMul(&s, a, b)
	ScMulAdd(&s1, a, b, &zero)

	assert.Equal(t, s, s1, "expected same output")
}

func BenchmarkScMul(bench *testing.B) {
	var s [32]byte
	a := rnd32BytesBench(bench)
	b := rnd32BytesBench(bench)
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		ScMul(&s, a, b)
	}
}

func BenchmarkScMulAdd(bench *testing.B) {
	var s, zero [32]byte
	a := rnd32BytesBench(bench)
	b := rnd32BytesBench(bench)
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		ScMulAdd(&s, a, b, &zero)
	}
}

func BenchmarkPointMult(bench *testing.B) {
	data := rnd32BytesBench(bench)
	var A ExtendedGroupElement
	GeScalarMultBase(&A, data)

	var A2 ProjectiveGroupElement
	a := rnd32BytesBench(bench)

	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		GeScalarMultVartime(&A2, a, &A)
	}
}

func BenchmarkDoublePointMult(bench *testing.B) {
	var zero [32]byte
	data := rnd32BytesBench(bench)

	var A ExtendedGroupElement
	GeScalarMultBase(&A, data)

	var A2 ProjectiveGroupElement
	a := rnd32BytesBench(bench)

	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		GeDoubleScalarMultVartime(&A2, a, &A, &zero)
	}
}

func BenchmarkProj2Ext(bench *testing.B) {
	data := rnd32BytesBench(bench)

	var A3 ExtendedGroupElement
	GeScalarMultBase(&A3, data)
	var A ProjectiveGroupElement
	A3.ToProjective(&A)

	var A2 ExtendedGroupElement
	bench.ResetTimer()

	for i := 0; i < bench.N; i++ {
		A.ToExtended(&A2)
	}
}

func BenchmarkProjBytesExt(bench *testing.B) {
	data := rnd32BytesBench(bench)

	var A3 ExtendedGroupElement
	GeScalarMultBase(&A3, data)
	var A ProjectiveGroupElement
	A3.ToProjective(&A)

	var A2 ExtendedGroupElement
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		A.ProjBytesExt(&A2)
	}
}

func BenchmarkInvertModL(b *testing.B) {
	var x, xInv [32]byte
	x[0] = byte(2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvertModL(&xInv, &x)
	}
}

func TestInvertModLOne(t *testing.T) {
	var x, xInv, z [32]byte
	x[0] = byte(1)
	InvertModL(&xInv, &x)
	assert.Equal(t, "1", ToInt(xInv[:]).String())
	ScMulAdd(&x, &x, &xInv, &z)
	outVal := ToInt(x[:])
	assert.Equal(t, "1", outVal.String(), "expected 0 * 0 == 0")
}

func TestInvertModL2(t *testing.T) {
	var x, xInv, z [32]byte
	x[0] = byte(2)
	InvertModL(&xInv, &x)
	xInvStr := ToInt(xInv[:]).String()
	assert.Equal(t, INV_2, xInvStr)

	ScMulAdd(&x, &x, &xInv, &z)
	outVal := ToInt(x[:]).String()
	assert.Equal(t, "1", outVal, "expected x * xInv == 1")
}

func TestMult(t *testing.T) {

	var zero [32]byte
	data := rnd32Bytes(t)
	x := rnd32Bytes(t)

	// Instead of creating a point A from random bytes, we take A = b*B for random b.
	// Note that A is random in <B>, but not in E -- need to fix this some how:
	// Take A = a*A' (or = a*A' + b*B) for "full order" A'
	//var A2 ExtendedGroupElement
	//ok := A2.FromBytes(data)
	//assert.True(t, ok, "failed to create extended group element")
	var A ExtendedGroupElement
	GeScalarMultBase(&A, data)

	var EC_PK, EC_PK1 ProjectiveGroupElement
	GeDoubleScalarMultVartime(&EC_PK, x, &A, &zero)
	GeScalarMultVartime(&EC_PK1, x, &A)

	var pk, pk1 [32]byte
	EC_PK.ToBytes(&pk)
	EC_PK1.ToBytes(&pk1)

	if !bytes.Equal(pk[:], pk1[:]) {
		t.Errorf("expected same public key")
	}
}

func TestProjective2Extended(t *testing.T) {

	data := rnd32Bytes(t)

	// Instead of creating a point A from random bytes, we take A = b*B for random b.
	// Note that A is random in <B>, but not in E -- need to fix this some how:
	// Take A = a*A' (or = a*A' + b*B) for "full order" A'
	//var A3 ExtendedGroupElement
	//ok := A3.FromBytes(data)
	//assert.True(t, ok, "failed to create extended group element")
	//var A ProjectiveGroupElement
	//A3.ToProjective(&A)

	var A3 ExtendedGroupElement
	GeScalarMultBase(&A3, data)
	var A ProjectiveGroupElement
	A3.ToProjective(&A)

	var A2 ExtendedGroupElement
	A.ProjBytesExt(&A2)

	//var buff [32]byte
	//A.ToBytes(&buff)
	//var A2 ExtendedGroupElement
	//ok2 := A2.FromBytes(&buff)
	//assert.True(t, ok2, "failed to create extended group element")

	var A2b ExtendedGroupElement
	A.ToExtended(&A2b)

	var point1, point1b [32]byte
	A2.ToBytes(&point1)
	A2b.ToBytes(&point1b)

	if !bytes.Equal(point1[:], point1b[:]) {
		t.Errorf("expected same point")
	}
}

func TestInvertModL17(t *testing.T) {
	var x, xInv, z [32]byte
	x[0] = byte(17)
	InvertModL(&xInv, &x)
	xInvStr := ToInt(xInv[:]).String()
	assert.Equal(t, INV_17, xInvStr)
	ScMulAdd(&x, &x, &xInv, &z)
	outVal := ToInt(x[:]).String()
	assert.Equal(t, "1", outVal, "expected x * xInv == 1")
}

func TestInvertModLRnd(testing *testing.T) {
	var tinv, z, out [32]byte
	for i := 1; i < 100; i++ {
		t := rnd32Bytes(testing)
		InvertModL(&tinv, t)
		ScMulAdd(&out, t, &tinv, &z)
		assert.Equal(testing, "1", ToInt(out[:]).String(), "expected t * tinv to equal 1")
	}
}

// ToInt returns a big int with the value of 256^0*b[0]+256^1*b[1]+...+256^31*b[len(b)-1]
// b must be a non-empty bytes slice. ToInt is a test helper function.
func ToInt(b []byte) *big.Int {
	res := big.NewInt(0)
	mul := big.NewInt(0)
	c := big.NewInt(256)
	t := big.NewInt(0)
	data := big.NewInt(0)
	l := len(b)

	for i := 0; i < l; i++ {

		// 256^i
		mul = mul.Exp(c, big.NewInt(int64(i)), nil)

		// res[i] = 256^i * b[i]
		data.SetUint64(uint64(b[i]))
		t = t.Mul(data, mul)
		res = res.Add(res, t)
	}
	return res
}

func rnd32Bytes(t *testing.T) *[32]byte {
	var d [32]byte
	n, err := rand.Read(d[:])
	assert.NoError(t, err, "no system entropy")
	assert.Equal(t, 32, n, "expected 32 bytes of entropy")
	return &d
}

func rnd32BytesBench(b *testing.B) *[32]byte {
	var d [32]byte
	n, err := rand.Read(d[:])
	assert.NoError(b, err, "no system entropy")
	assert.Equal(b, 32, n, "expected 32 bytes of entropy")
	return &d
}
