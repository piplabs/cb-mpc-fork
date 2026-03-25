package cgobinding

/*
#cgo CXXFLAGS: -std=c++17
#include <stdlib.h>
#include "tdh2.h"
*/
import "C"

import (
	"fmt"
	"runtime"
)

// TDH2PublicKeyRef is an opaque reference to a native tdh2::public_key_t.
// It must be released with Free() when no longer needed.
type TDH2PublicKeyRef C.tdh2_public_key_ref

// Free releases the native public key object.
func (ref TDH2PublicKeyRef) Free() {
	C.free_tdh2_public_key(C.tdh2_public_key_ref(ref))
}

// TDH2PublicKeyToBytes serializes the public key to bytes.
func TDH2PublicKeyToBytes(ref TDH2PublicKeyRef) []byte {
	var out CMEM
	rv := C.tdh2_public_key_to_bytes(C.tdh2_public_key_ref(ref), (*C.cmem_t)(&out))
	if rv != 0 {
		return nil
	}
	return CMEMGet(out)
}

// TDH2PublicKeyFromBytes deserializes a public key from bytes.
func TDH2PublicKeyFromBytes(data []byte) (TDH2PublicKeyRef, error) {
	var out C.tdh2_public_key_ref
	rv := C.tdh2_public_key_from_bytes(cmem(data), &out)
	if rv != 0 {
		return TDH2PublicKeyRef{}, fmt.Errorf("tdh2 public key from bytes failed: %v", rv)
	}
	return TDH2PublicKeyRef(out), nil
}

// TDH2PublicKeyFromPoint creates a public key from a serialized elliptic curve point Q.
// Gamma is derived automatically per the TDH2 spec.
func TDH2PublicKeyFromPoint(pointBytes []byte) (TDH2PublicKeyRef, error) {
	var out C.tdh2_public_key_ref
	rv := C.tdh2_public_key_from_point(cmem(pointBytes), &out)
	if rv != 0 {
		return TDH2PublicKeyRef{}, fmt.Errorf("tdh2 public key from point failed: %v", rv)
	}
	return TDH2PublicKeyRef(out), nil
}

// TDH2Encrypt encrypts plaintext under the TDH2 public key.
func TDH2Encrypt(pubKey TDH2PublicKeyRef, plain, label []byte) ([]byte, error) {
	var out CMEM
	rv := C.tdh2_encrypt(C.tdh2_public_key_ref(pubKey), cmem(plain), cmem(label), (*C.cmem_t)(&out))
	if rv != 0 {
		return nil, fmt.Errorf("tdh2 encrypt failed: %v", rv)
	}
	return CMEMGet(out), nil
}

// TDH2Verify verifies the ciphertext proof against the public key and label.
func TDH2Verify(pubKey TDH2PublicKeyRef, ciphertext, label []byte) error {
	rv := C.tdh2_verify(C.tdh2_public_key_ref(pubKey), cmem(ciphertext), cmem(label))
	if rv != 0 {
		return fmt.Errorf("tdh2 verify failed: %v", rv)
	}
	return nil
}

// TDH2PartialDecrypt produces a partial decryption for one party.
// pid is the party's integer ID; shareScalar is the raw scalar x (bn_t bytes).
func TDH2PartialDecrypt(pid int, shareScalar []byte, pubKey TDH2PublicKeyRef, ciphertext, label []byte) ([]byte, error) {
	var out CMEM
	rv := C.tdh2_partial_decrypt(C.int(pid), cmem(shareScalar), C.tdh2_public_key_ref(pubKey), cmem(ciphertext), cmem(label), (*C.cmem_t)(&out))
	if rv != 0 {
		return nil, fmt.Errorf("tdh2 partial decrypt failed: %v", rv)
	}
	return CMEMGet(out), nil
}

// TDH2CombineAC combines a quorum of partial decryptions under an access structure.
// names, pubShares, and pdValues are parallel slices (one per quorum member).
func TDH2CombineAC(ac C_AcPtr, pubKey TDH2PublicKeyRef, names, pubShares [][]byte, ciphertext, label []byte, pdValues [][]byte) ([]byte, error) {
	if len(names) != len(pubShares) || len(names) != len(pdValues) {
		return nil, fmt.Errorf("names, pubShares, pdValues must have equal length")
	}

	var out CMEM
	namesPin := makeCmems(names)
	psPin := makeCmems(pubShares)
	pdPin := makeCmems(pdValues)

	rv := C.tdh2_combine_ac((*C.crypto_ss_ac_ref)(&ac), C.tdh2_public_key_ref(pubKey), namesPin.c, psPin.c, cmem(ciphertext), cmem(label), pdPin.c, (*C.cmem_t)(&out))
	runtime.KeepAlive(namesPin)
	runtime.KeepAlive(psPin)
	runtime.KeepAlive(pdPin)
	if rv != 0 {
		return nil, fmt.Errorf("tdh2 combine AC failed: %v", rv)
	}
	return CMEMGet(out), nil
}

