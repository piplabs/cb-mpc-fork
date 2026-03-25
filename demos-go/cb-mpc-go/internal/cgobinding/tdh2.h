#pragma once

#include <stdint.h>

#include <cbmpc/core/cmem.h>

#include "ac.h"
#include "curve.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque reference to a heap-allocated native tdh2::public_key_t.
// Must be released exactly once via free_tdh2_public_key.
typedef struct tdh2_public_key_ref {
  void* opaque;
} tdh2_public_key_ref;

// Release the native public key object.
void free_tdh2_public_key(tdh2_public_key_ref ref);

// Serialize the public key to bytes (round-trips with tdh2_public_key_from_bytes).
int tdh2_public_key_to_bytes(tdh2_public_key_ref ref, cmem_t* out);

// Deserialize a public key from bytes previously produced by tdh2_public_key_to_bytes.
int tdh2_public_key_from_bytes(cmem_t bytes, tdh2_public_key_ref* out);

// Construct a public key from a raw serialized elliptic curve point Q.
// Gamma is derived automatically per the TDH2 spec.
int tdh2_public_key_from_point(cmem_t point_cmem, tdh2_public_key_ref* out);

// Encrypt plaintext under the TDH2 public key.
int tdh2_encrypt(tdh2_public_key_ref pub_key, cmem_t plain, cmem_t label, cmem_t* ciphertext_out);

// Verify the ciphertext proof against the public key and label.
// Returns 0 on success, non-zero on invalid proof.
int tdh2_verify(tdh2_public_key_ref pub_key, cmem_t ciphertext, cmem_t label);

// Produce a partial decryption for one party.
//   pid          – the party's integer ID (must match the ID used during share generation)
//   share_scalar – the raw scalar x (bn_t bytes) for this party
int tdh2_partial_decrypt(int pid, cmem_t share_scalar, tdh2_public_key_ref pub_key, cmem_t ciphertext,
                          cmem_t label, cmem_t* partial_decryption_out);

// Combine a quorum of partial decryptions under an access structure to recover the plaintext.
// names, pub_shares, and pd_values are parallel arrays of equal length (one entry per quorum member).
//   names      – leaf path strings identifying the quorum members
//   pub_shares – serialized ecc_point_t for each quorum member (Qi = xi * G)
//   pd_values  – serialized partial_decryption_t for each quorum member
int tdh2_combine_ac(crypto_ss_ac_ref* ac_ptr, tdh2_public_key_ref pub_key, cmems_t names, cmems_t pub_shares,
                    cmem_t ciphertext, cmem_t label, cmems_t pd_values, cmem_t* plain_out);


#ifdef __cplusplus
}  // extern "C"
#endif
