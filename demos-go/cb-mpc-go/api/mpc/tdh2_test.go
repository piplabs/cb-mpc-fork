package mpc

import (
	"math/big"
	"testing"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/transport/mocknet"

	"github.com/stretchr/testify/require"
)

// tdh2AcShares holds the output of tdh2SetupAcShares.
type tdh2AcShares struct {
	pubKey    *TDH2PublicKey
	pubShares map[string][]byte           // leaf name → Qi point bytes
	prvShares map[string]*TDH2PrivateShare // leaf name → raw scalar
	pids      map[string]int               // leaf name → explicit PID
}

// tdh2SetupAcShares performs a (threshold)-of-(n) Shamir split in pure Go and
// loads the result through the TDH2 API. Shares are constructed at the API level
// without any dedicated C generation helper:
//
//  1. Random polynomial f of degree (threshold-1) with f(0) = x is built
//     using math/big over the curve order.
//  2. Each party's share is f(pid) mod order.
//  3. Public key is x*G; public shares are f(pid)*G.
//
// explicitPIDs must have the same length as pnames; each entry is the PID
// assigned to the corresponding party and stored in the AccessStructure.
func tdh2SetupAcShares(t *testing.T, pnames []string, explicitPIDs []int, threshold int, cv curve.Curve) (*AccessStructure, *tdh2AcShares) {
	t.Helper()
	n := len(pnames)
	require.Len(t, explicitPIDs, n, "explicitPIDs must match pnames length")

	// Build access structure with the caller-supplied explicit PIDs.
	kids := make([]*AccessNode, n)
	for i, name := range pnames {
		pid := explicitPIDs[i]
		kids[i] = &AccessNode{Name: name, Kind: KindLeaf, ExplicitPID: &pid}
	}
	as := &AccessStructure{Root: Threshold("", threshold, kids...), Curve: cv}

	// Sample the secret and polynomial coefficients over the curve order.
	q := new(big.Int).SetBytes(cv.Order())

	xScalar, err := cv.RandomScalar()
	require.NoError(t, err)
	x := new(big.Int).SetBytes(xScalar.Bytes)

	// Polynomial coefficients: f(z) = x + a[1]*z + ... + a[t-1]*z^(t-1) mod q
	coeffs := make([]*big.Int, threshold)
	coeffs[0] = x
	for i := 1; i < threshold; i++ {
		ai, err := cv.RandomScalar()
		require.NoError(t, err)
		coeffs[i] = new(big.Int).SetBytes(ai.Bytes)
	}

	// Evaluate f at an arbitrary point.
	evalAt := func(pid int) *big.Int {
		z := big.NewInt(int64(pid))
		acc := new(big.Int)
		zPow := new(big.Int).SetInt64(1)
		for _, c := range coeffs {
			acc.Add(acc, new(big.Int).Mul(c, zPow))
			acc.Mod(acc, q)
			zPow.Mul(zPow, z)
			zPow.Mod(zPow, q)
		}
		return acc
	}

	// Compute public key Q = x*G.
	pubKeyPt, err := cv.MultiplyGenerator(xScalar)
	require.NoError(t, err)
	defer pubKeyPt.Free()

	pk, err := TDH2PublicKeyFromPoint(pubKeyPt.Bytes())
	require.NoError(t, err)
	t.Cleanup(pk.Free)

	// Compute per-party shares using the caller-supplied PIDs.
	pubShares := make(map[string][]byte, n)
	prvShares := make(map[string]*TDH2PrivateShare, n)
	pids := make(map[string]int, n)

	for i, name := range pnames {
		pid := explicitPIDs[i]
		xi := evalAt(pid)

		// Pad to the same byte length as the order (big-endian).
		scalarBytes := make([]byte, len(cv.Order()))
		xi.FillBytes(scalarBytes)

		xiScalar := &curve.Scalar{Bytes: scalarBytes}
		Qi, err := cv.MultiplyGenerator(xiScalar)
		require.NoError(t, err)
		defer Qi.Free()

		pubShares[name] = Qi.Bytes()
		prvShares[name] = &TDH2PrivateShare{Bytes: scalarBytes}
		pids[name] = pid
	}

	return as, &tdh2AcShares{
		pubKey:    pk,
		pubShares: pubShares,
		prvShares: prvShares,
		pids:      pids,
	}
}

// TestTDH2AcEncryptDecrypt verifies the full workflow for threshold secret sharing
// used for TDH2 encryption and decryption under an access structure:
// load shares → encrypt → verify → per-party partial decrypt → combine.
func TestTDH2AcEncryptDecrypt(t *testing.T) {
	const threshold = 3

	cv, err := curve.NewEd25519()
	require.NoError(t, err)
	defer cv.Free()

	pnames := mocknet.GeneratePartyNames(5)
	explicitPIDs := []int{1, 2, 3, 4, 5}
	as, shares := tdh2SetupAcShares(t, pnames, explicitPIDs, threshold, cv)

	plaintext := []byte("threshold ac tdh2 test")
	label := []byte("test-label")

	// Encrypt.
	ct, err := TDH2Encrypt(shares.pubKey, plaintext, label)
	require.NoError(t, err)
	require.NotEmpty(t, ct.Bytes)

	// Verify ciphertext before decryption.
	require.NoError(t, ct.Verify(shares.pubKey, label))

	// All parties produce partial decryptions.
	partialDecryptions := make(map[string]*TDH2PartialDecryption, len(pnames))
	for _, name := range pnames {
		pd, err := TDH2PartialDecrypt(shares.pids[name], shares.prvShares[name], shares.pubKey, ct, label)
		require.NoError(t, err, "partial decrypt failed for %s", name)
		partialDecryptions[name] = pd
	}

	// Combine using all parties (exceeding threshold is fine).
	recovered, err := TDH2Combine(as, shares.pubKey, shares.pubShares, ct, label, partialDecryptions)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)
}

// TestTDH2AcEncryptDecryptThresholdQuorum verifies that exactly threshold parties
// suffice for decryption without requiring all n parties.
func TestTDH2AcEncryptDecryptThresholdQuorum(t *testing.T) {
	const threshold = 3

	cv, err := curve.NewEd25519()
	require.NoError(t, err)
	defer cv.Free()

	pnames := mocknet.GeneratePartyNames(5)
	explicitPIDs := []int{1, 2, 3, 4, 5}
	as, shares := tdh2SetupAcShares(t, pnames, explicitPIDs, threshold, cv)

	plaintext := []byte("quorum decryption test")
	label := []byte("quorum-label")

	ct, err := TDH2Encrypt(shares.pubKey, plaintext, label)
	require.NoError(t, err)

	// Only the first `threshold` parties participate.
	quorum := pnames[:threshold]
	partialDecryptions := make(map[string]*TDH2PartialDecryption, threshold)
	for _, name := range quorum {
		pd, err := TDH2PartialDecrypt(shares.pids[name], shares.prvShares[name], shares.pubKey, ct, label)
		require.NoError(t, err)
		partialDecryptions[name] = pd
	}

	recovered, err := TDH2Combine(as, shares.pubKey, shares.pubShares, ct, label, partialDecryptions)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)
}

// TestTDH2PublicKeyRoundTrip verifies that the public key serializes and deserializes correctly.
func TestTDH2PublicKeyRoundTrip(t *testing.T) {
	cv, err := curve.NewEd25519()
	require.NoError(t, err)
	defer cv.Free()

	pnames := mocknet.GeneratePartyNames(3)
	explicitPIDs := []int{1, 2, 3}
	_, shares := tdh2SetupAcShares(t, pnames, explicitPIDs, 2, cv)

	pkBytes := shares.pubKey.Bytes()
	require.NotEmpty(t, pkBytes)

	pk2, err := TDH2PublicKeyFromBytes(pkBytes)
	require.NoError(t, err)
	defer pk2.Free()

	require.Equal(t, pkBytes, pk2.Bytes())
}
