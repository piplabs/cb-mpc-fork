package mpc

import (
	"fmt"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/internal/cgobinding"
)

// TDH2PublicKey wraps a native TDH2 public key object.
// It must be released by calling Free() when no longer needed.
type TDH2PublicKey struct {
	ref   cgobinding.TDH2PublicKeyRef
	bytes []byte
}

// Free releases the underlying native object.
func (pk *TDH2PublicKey) Free() {
	if pk != nil && pk.ref != (cgobinding.TDH2PublicKeyRef{}) {
		pk.ref.Free()
	}
}

// Bytes returns the serialized form of the public key (lazy, cached).
func (pk *TDH2PublicKey) Bytes() []byte {
	if pk.bytes == nil {
		pk.bytes = cgobinding.TDH2PublicKeyToBytes(pk.ref)
	}
	return pk.bytes
}

// TDH2PublicKeyFromBytes deserializes a TDH2 public key from bytes.
func TDH2PublicKeyFromBytes(data []byte) (*TDH2PublicKey, error) {
	ref, err := cgobinding.TDH2PublicKeyFromBytes(data)
	if err != nil {
		return nil, err
	}
	return &TDH2PublicKey{ref: ref, bytes: data}, nil
}

// TDH2PublicKeyFromPoint constructs a TDH2 public key from a serialized elliptic curve point Q.
// Gamma is derived automatically per the TDH2 spec.
func TDH2PublicKeyFromPoint(pointBytes []byte) (*TDH2PublicKey, error) {
	ref, err := cgobinding.TDH2PublicKeyFromPoint(pointBytes)
	if err != nil {
		return nil, err
	}
	return &TDH2PublicKey{ref: ref}, nil
}

// TDH2PrivateShare holds the raw scalar for one party's TDH2 share.
// The party's PID is kept separately and passed explicitly to TDH2PartialDecrypt.
type TDH2PrivateShare struct {
	Bytes []byte // raw bn_t scalar
}

// TDH2Ciphertext is a serialized TDH2 ciphertext.
type TDH2Ciphertext struct {
	Bytes []byte
}

// TDH2PartialDecryption is a serialized partial decryption from a single party.
type TDH2PartialDecryption struct {
	Bytes []byte
}

// ─── Encryption ──────────────────────────────────────────────────────────────

// TDH2Encrypt encrypts plaintext under the TDH2 public key.
func TDH2Encrypt(pubKey *TDH2PublicKey, plain, label []byte) (*TDH2Ciphertext, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	ctBytes, err := cgobinding.TDH2Encrypt(pubKey.ref, plain, label)
	if err != nil {
		return nil, err
	}
	return &TDH2Ciphertext{Bytes: ctBytes}, nil
}

// ─── Verification ────────────────────────────────────────────────────────────

// TDH2Verify checks the ciphertext proof against the public key and label.
func TDH2Verify(pubKey *TDH2PublicKey, ciphertext, label []byte) error {
	if pubKey == nil {
		return fmt.Errorf("public key cannot be nil")
	}
	return cgobinding.TDH2Verify(pubKey.ref, ciphertext, label)
}

// Verify is a convenience method on TDH2Ciphertext.
func (ct *TDH2Ciphertext) Verify(pubKey *TDH2PublicKey, label []byte) error {
	if pubKey == nil {
		return fmt.Errorf("public key cannot be nil")
	}
	return cgobinding.TDH2Verify(pubKey.ref, ct.Bytes, label)
}

// ─── Per-party partial decryption ────────────────────────────────────────────

// TDH2PartialDecrypt produces a partial decryption for one party.
// pid is the party's integer ID (as assigned during key generation).
func TDH2PartialDecrypt(pid int, share *TDH2PrivateShare, pubKey *TDH2PublicKey, ct *TDH2Ciphertext, label []byte) (*TDH2PartialDecryption, error) {
	if share == nil {
		return nil, fmt.Errorf("private share cannot be nil")
	}
	if pubKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	if ct == nil {
		return nil, fmt.Errorf("ciphertext cannot be nil")
	}
	pdBytes, err := cgobinding.TDH2PartialDecrypt(pid, share.Bytes, pubKey.ref, ct.Bytes, label)
	if err != nil {
		return nil, err
	}
	return &TDH2PartialDecryption{Bytes: pdBytes}, nil
}

// ─── AC combining ────────────────────────────────────────────────────────────

// TDH2Combine recovers the plaintext by combining a quorum of partial decryptions
// under the given access structure.
//
// pubShares maps every leaf path name to its public share (ecc_point_t bytes).
// Providing all leaves is safe; only the quorum members present in partialDecryptions
// are used.
//
// partialDecryptions maps the contributing party's leaf path name to their
// partial decryption. The set of names must form a valid quorum.
func TDH2Combine(as *AccessStructure, pubKey *TDH2PublicKey, pubShares map[string][]byte, ct *TDH2Ciphertext, label []byte, partialDecryptions map[string]*TDH2PartialDecryption) ([]byte, error) {
	if as == nil {
		return nil, fmt.Errorf("access structure cannot be nil")
	}
	if pubKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	if ct == nil {
		return nil, fmt.Errorf("ciphertext cannot be nil")
	}
	if len(partialDecryptions) == 0 {
		return nil, fmt.Errorf("partialDecryptions cannot be empty")
	}

	// Build parallel slices for quorum members only.
	names := make([][]byte, 0, len(partialDecryptions))
	psSlice := make([][]byte, 0, len(partialDecryptions))
	pdSlice := make([][]byte, 0, len(partialDecryptions))

	for name, pd := range partialDecryptions {
		if pd == nil {
			return nil, fmt.Errorf("partial decryption for %s is nil", name)
		}
		ps, ok := pubShares[name]
		if !ok {
			return nil, fmt.Errorf("missing public share for %s", name)
		}
		names = append(names, []byte(name))
		psSlice = append(psSlice, ps)
		pdSlice = append(pdSlice, pd.Bytes)
	}

	acPtr := as.toCryptoAC()
	defer cgobinding.FreeAccessStructure(acPtr)

	return cgobinding.TDH2CombineAC(acPtr, pubKey.ref, names, psSlice, ct.Bytes, label, pdSlice)
}
