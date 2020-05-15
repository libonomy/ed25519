
// ed25519 extensions

package ed25519

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/evdatsion/ed25519/internal/edwards25519"
)

// ExtractPublicKey extracts the signer's public key given a message and its signature.
// Note that signature must be created using Sign2() and NOT using Sign().
// It will panic if len(sig) is not SignatureSize.
func ExtractPublicKey(message, sig []byte) (PublicKey, error) {

	if l := len(sig); l != SignatureSize || sig[63]&224 != 0 {
		return nil, errors.New("ed25519: bad signature format")
	}

	h := sha512.New()
	h.Write(sig[:32])
	// we remove the public key from the hash
	//h.Write(privateKey[32:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var hInv [32]byte
	edwards25519.InvertModL(&hInv, &hReduced)

	var s [32]byte
	if l := copy(s[:], sig[32:]); l != PublicKeySize {
		return nil, errors.New("memory copy failed")
	}

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !edwards25519.ScMinimal(&s) {
		return nil, errors.New("invalid signature")
	}

	// var zero [32]byte
	var one [32]byte
	one[0] = byte(1)

	// Extract R = sig[32:] as a point on the curve (and compute the inverse of R)
	var R edwards25519.ExtendedGroupElement
	var r [32]byte
	copy(r[:], sig[:32])
	if ok := R.FromBytes(&r); !ok {
		return nil, errors.New("failed to create extended group element from s")
	}

	// The following lines make R -> -R
	edwards25519.FeNeg(&R.X, &R.X)
	edwards25519.FeNeg(&R.T, &R.T)
	var A edwards25519.ProjectiveGroupElement
	var A2 edwards25519.ExtendedGroupElement
	edwards25519.GeDoubleScalarMultVartime(&A, &one, &R, &s)
	A.ToExtended(&A2)

	// THESE COMMENTS ARE OBSOLETE (afterwards we added ToExtended() ) -- KEPT TO REMIND OURSELVES THE LOGIC
	// We need to convert A from projective to extended group element
	// ToBytes takes projective
	// FromBytes return extended
	// Let's try....  [in general there should be a smarter way of doing this, so remember to look into this]

	// following is old commands, which we keep for benchmarking
	//var buff [32]byte
	//A.ToBytes(&buff)
	//var A2 edwards25519.ExtendedGroupElement
	//if ok := A2.FromBytes(&buff); !ok {
	//	return nil, errors.New("failed to create an extended group element A2 from A")
	//}

	var EC_PK edwards25519.ProjectiveGroupElement
	// This is the old command, used for the built-in scalar multiplication function
	//edwards25519.GeDoubleScalarMultVartime(&EC_PK, &hInv, &A2, &zero)
	edwards25519.GeScalarMultVartime(&EC_PK, &hInv, &A2)

	var pubKey [PublicKeySize]byte

	// EC_PK is supposed to be the public key as an elliptic curve point, we apply ToBytes
	EC_PK.ToBytes(&pubKey)
	return pubKey[:], nil
}

// NewDerivedKeyFromSeed calculates a private key from a 32 bytes random seed, an integer index and salt
func NewDerivedKeyFromSeed(seed []byte, index uint64, salt []byte) PrivateKey {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	digest := sha512.New()
	digest.Write(seed)
	digest.Write(salt)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, index)
	digest.Write(buf)

	return NewKeyFromSeed(digest.Sum(nil)[:SeedSize])
}

// Sign2 signs the message with privateKey and returns a signature.
// The signature may be verified using Verify2(), if the signer's public key is known.
// The signature returned by this method can be used together with the message
// to extract the public key using ExtractPublicKey()
// It will panic if len(privateKey) is not PrivateKeySize.
func Sign2(privateKey PrivateKey, message []byte) []byte {

	// COMMENTS in the code refer to Algorithm 1 in https://eprint.iacr.org/2017/985.pdf

	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()

	// privateKey follows from NewKeyFromSeed();
	// it seems that the first 32 bytes is 'a' as in line 2 in "Algorithm 1",
	// and the last 32 bytes is the (encoding) of the public key (elliptic curve point,
	// as in line 4 in "Algorithm 1").
	h.Write(privateKey[:32])

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64 // this is the final value for 'a'

	h.Reset()
	// This seems to be 'b' as in line 3 in "Algorithm 1",
	// however it seems that it is obtained by hashing of (non-final 'a'),
	// rather by the way it is described in "Algorithm 1"
	h.Write(digest1[32:])
	h.Write(message)

	// line 5 in "Algorithm 1": creates r
	h.Sum(messageDigest[:0])

	// looks like reduction mod l, this is the final r
	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)

	// line 6 in "Algorithm 1": creates R
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	// we remove the public key from the hash
	//h.Write(privateKey[32:])

	// line 7: creates h
	h.Write(message)
	h.Sum(hramDigest[:0])

	var hramDigestReduced [32]byte

	// this is the final h
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	// line 8: s = h*a + r
	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := make([]byte, SignatureSize)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature
}

// Verify2 verifies a signature created with Sign2(),
// assuming the verifier possesses the public key.
func Verify2(publicKey PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(sig[:32])
	// we remove the public key from the hash
	// h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var R edwards25519.ProjectiveGroupElement
	var s [32]byte
	copy(s[:], sig[32:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !edwards25519.ScMinimal(&s) {
		return false
	}

	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &s)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return bytes.Equal(sig[:32], checkR[:])
}
