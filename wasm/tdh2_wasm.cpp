/**
 * WASM wrapper for cb-mpc TDH2 functions.
 *
 * This file provides a simplified C API for the TypeScript SDK, wrapping the
 * existing CGo binding layer (tdh2.cpp, ac.cpp, curve.cpp) with
 * Emscripten-compatible memory management.
 *
 * All returned byte buffers are malloc'd and must be freed by the caller
 * (the JS side calls Module._free).
 */

#include <emscripten/emscripten.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cbmpc/core/buf.h>
#include <cbmpc/core/cmem.h>
#include <cbmpc/core/convert.h>
#include <cbmpc/core/extended_uint.h>
#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/secret_sharing.h>
#include <cbmpc/crypto/tdh2.h>

using namespace coinbase;
using namespace coinbase::crypto;
using namespace coinbase::crypto::tdh2;
using tdh2_ciphertext_t = coinbase::crypto::tdh2::ciphertext_t;
using node_t = coinbase::crypto::ss::node_t;
using node_e = coinbase::crypto::ss::node_e;

extern "C" {

// ============ Result struct for returning bytes to JS =============
// JS reads out_ptr and out_size, then copies the data, then calls free(out_ptr).

/**
 * Create a TDH2 public key from a serialized elliptic curve point.
 *
 * @param point_data  Serialized EC point bytes (curve-code prefixed)
 * @param point_size  Size of point_data
 * @param out_handle  Output: opaque handle (cast to int for JS)
 * @return 0 on success
 */
EMSCRIPTEN_KEEPALIVE
int wasm_tdh2_pub_key_from_point(const uint8_t* point_data, int point_size, int* out_handle) {
  ecc_point_t Q;
  mem_t point_mem(point_data, point_size);
  error_t rv = coinbase::deser(point_mem, Q);
  if (rv) return rv;

  public_key_t* pk = new public_key_t(Q);
  *out_handle = (int)(intptr_t)pk;
  return 0;
}

/**
 * Free a TDH2 public key handle.
 */
EMSCRIPTEN_KEEPALIVE
void wasm_tdh2_free_pub_key(int handle) {
  if (handle) {
    delete (public_key_t*)(intptr_t)handle;
  }
}

/**
 * TDH2 encrypt plaintext to a public key.
 *
 * @param pub_key_handle  Handle from wasm_tdh2_pub_key_from_point
 * @param plain_data      Plaintext bytes
 * @param plain_size      Plaintext size
 * @param label_data      Label bytes (associated data)
 * @param label_size      Label size
 * @param out_ptr         Output: pointer to malloc'd ciphertext bytes
 * @param out_size        Output: size of ciphertext
 * @return 0 on success
 */
EMSCRIPTEN_KEEPALIVE
int wasm_tdh2_encrypt(int pub_key_handle,
                      const uint8_t* plain_data, int plain_size,
                      const uint8_t* label_data, int label_size,
                      uint8_t** out_ptr, int* out_size) {
  if (!pub_key_handle || !out_ptr || !out_size) return -1;

  public_key_t* pk = (public_key_t*)(intptr_t)pub_key_handle;
  mem_t plain(plain_data, plain_size);
  mem_t label(label_data, label_size);

  tdh2_ciphertext_t ct = pk->encrypt(plain, label);
  buf_t out = coinbase::convert(ct);

  *out_size = out.size();
  *out_ptr = (uint8_t*)malloc(out.size());
  memcpy(*out_ptr, out.data(), out.size());
  return 0;
}

/**
 * Verify a TDH2 ciphertext.
 *
 * @return 0 if valid
 */
EMSCRIPTEN_KEEPALIVE
int wasm_tdh2_verify(int pub_key_handle,
                     const uint8_t* ct_data, int ct_size,
                     const uint8_t* label_data, int label_size) {
  if (!pub_key_handle) return -1;

  public_key_t* pk = (public_key_t*)(intptr_t)pub_key_handle;
  tdh2_ciphertext_t ct;
  error_t rv = coinbase::convert(ct, mem_t(ct_data, ct_size));
  if (rv) return rv;
  ct.L = buf_t(mem_t(label_data, label_size));
  return ct.verify(*pk, mem_t(label_data, label_size));
}

// ============ Access Structure =============

/**
 * Create a threshold node for an access structure.
 *
 * @param node_type   0 = leaf, 1 = threshold gate
 * @param name_data   Node name bytes (for leaves: validator identifier)
 * @param name_size   Name size
 * @param threshold   Threshold value (for gates)
 * @return Opaque handle
 */
EMSCRIPTEN_KEEPALIVE
int wasm_ac_new_node(int node_type, const uint8_t* name_data, int name_size, int threshold) {
  std::string name((const char*)name_data, name_size);
  node_t* node = new node_t(node_e(node_type), name, threshold);
  return (int)(intptr_t)node;
}

/**
 * Add a child node to a parent node.
 */
EMSCRIPTEN_KEEPALIVE
void wasm_ac_add_child(int parent_handle, int child_handle) {
  node_t* parent = (node_t*)(intptr_t)parent_handle;
  node_t* child = (node_t*)(intptr_t)child_handle;
  parent->add_child_node(child);
}

/**
 * Set an explicit PID on a node.
 */
EMSCRIPTEN_KEEPALIVE
void wasm_ac_set_node_pid(int node_handle, int pid) {
  node_t* node = (node_t*)(intptr_t)node_handle;
  node->set_explicit_pid(pid);
}

/**
 * Create an access structure from a root node and curve code.
 *
 * @param root_handle  Root node handle
 * @param curve_code   OpenSSL curve code (e.g., NID_X9_62_prime256v1)
 * @return Opaque AC handle
 */
EMSCRIPTEN_KEEPALIVE
int wasm_ac_new(int root_handle, int curve_code) {
  node_t* root = (node_t*)(intptr_t)root_handle;
  ecurve_t curve = ecurve_t::find(curve_code);

  ss::ac_t* ac = new ss::ac_t();
  if (curve) {
    ac->G = curve.generator();
  }
  ac->root = root;
  return (int)(intptr_t)ac;
}

/**
 * Free an access structure.
 */
EMSCRIPTEN_KEEPALIVE
void wasm_ac_free(int ac_handle) {
  if (ac_handle) {
    delete (ss::ac_t*)(intptr_t)ac_handle;
  }
}

// ============ TDH2 Combine =============

/**
 * Combine partial decryptions to recover plaintext.
 *
 * Memory layout for array parameters:
 *   names_offsets[n], names_data = concatenated name bytes
 *   pub_shares_offsets[n], pub_shares_data = concatenated pub share bytes
 *   partials_offsets[n], partials_data = concatenated partial bytes
 *
 * For simplicity, each array is passed as (data_ptr, count, sizes_array_ptr)
 * matching the cmems_t pattern.
 *
 * @param ac_handle       Access structure handle
 * @param pub_key_handle  TDH2 public key handle
 * @param n               Number of partials
 * @param names_data      Concatenated validator name bytes
 * @param names_sizes     Array of n ints: size of each name
 * @param pub_shares_data Concatenated pub share point bytes
 * @param pub_shares_sizes Array of n ints
 * @param ct_data         Serialized ciphertext
 * @param ct_size         Ciphertext size
 * @param label_data      Label bytes
 * @param label_size      Label size
 * @param partials_data   Concatenated partial decryption bytes
 * @param partials_sizes  Array of n ints
 * @param out_ptr         Output: pointer to malloc'd plaintext
 * @param out_size        Output: plaintext size
 * @return 0 on success
 */
EMSCRIPTEN_KEEPALIVE
int wasm_tdh2_combine(int ac_handle, int pub_key_handle, int n,
                      const uint8_t* names_data, const int* names_sizes,
                      const uint8_t* pub_shares_data, const int* pub_shares_sizes,
                      const uint8_t* ct_data, int ct_size,
                      const uint8_t* label_data, int label_size,
                      const uint8_t* partials_data, const int* partials_sizes,
                      uint8_t** out_ptr, int* out_size) {
  if (!ac_handle || !pub_key_handle || !out_ptr || !out_size) return -1;

  ss::ac_t* ac = (ss::ac_t*)(intptr_t)ac_handle;
  public_key_t* pk = (public_key_t*)(intptr_t)pub_key_handle;

  // Parse ciphertext (use convert to match Go bindings format)
  tdh2_ciphertext_t ct;
  error_t rv = coinbase::convert(ct, mem_t(ct_data, ct_size));
  if (rv) return rv;
  ct.L = buf_t(mem_t(label_data, label_size));

  // Build name → pub_share and name → partial_decryption maps
  ss::ac_pub_shares_t pub_shares;
  ss::party_map_t<partial_decryption_t> pds;

  int names_offset = 0;
  int pub_shares_offset = 0;
  int partials_offset = 0;

  for (int i = 0; i < n; i++) {
    std::string name((const char*)(names_data + names_offset), names_sizes[i]);
    names_offset += names_sizes[i];

    // Deserialize public share point
    ecc_point_t Qi(pk->Q.get_curve());
    mem_t pub_share_mem(pub_shares_data + pub_shares_offset, pub_shares_sizes[i]);
    rv = coinbase::deser(pub_share_mem, Qi);
    if (rv) return rv;
    pub_shares[name] = Qi;
    pub_shares_offset += pub_shares_sizes[i];

    // Deserialize partial decryption (use convert to match Go bindings format)
    partial_decryption_t pd;
    pd.Xi = ecc_point_t(pk->Q.get_curve());
    mem_t pd_mem(partials_data + partials_offset, partials_sizes[i]);
    rv = coinbase::convert(pd, pd_mem);
    if (rv) return rv;
    pds[name] = pd;
    partials_offset += partials_sizes[i];
  }

  buf_t plain;
  rv = combine(*ac, *pk, pub_shares, mem_t(label_data, label_size), pds, ct, plain);
  if (rv) return rv;

  *out_size = plain.size();
  *out_ptr = (uint8_t*)malloc(plain.size());
  memcpy(*out_ptr, plain.data(), plain.size());
  return 0;
}

/**
 * Seed OpenSSL's RAND with external entropy.
 *
 * WASM has no OS entropy source (/dev/urandom, getentropy). The JS caller
 * must provide entropy from crypto.getRandomValues() and call this function
 * before any operation that uses RAND_bytes() (e.g. TDH2 encrypt).
 *
 * @param data  Pointer to entropy bytes
 * @param size  Number of bytes (recommended: >= 48)
 */
EMSCRIPTEN_KEEPALIVE
void wasm_seed_random(const uint8_t* data, int size) {
  // Use both RAND_seed and RAND_add to ensure the DRBG is properly seeded.
  // OpenSSL 3.x requires the DRBG to be initialized; RAND_add with high
  // entropy estimate (== size) marks the pool as sufficiently seeded.
  RAND_seed(data, size);
  RAND_add(data, size, (double)size);
}

/**
 * Test bn_t::rand range correctness.
 * Returns 0 if OK, or error code.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_test_bn_rand() {
  // Ed25519 order
  bn_t q_val = bn_t::from_hex("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED");
  mod_t q(q_val, true);

  for (int i = 0; i < 100; i++) {
    bn_t r = bn_t::rand(q_val);
    if (r.sign() < 0) return 1;  // negative
    if (r >= q_val) return 2;     // out of range
    // Also test hash_number().mod(q)
  }
  return 0;
}

/**
 * Diagnostic: test uint128 arithmetic correctness in WASM.
 * Returns 0 if all tests pass, or a positive error code identifying the failure.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_test_uint128() {
  // Test 1: 128-bit multiplication
  unsigned __int128 a = (unsigned __int128)0xFFFFFFFFFFFFFFFFULL * 0xFFFFFFFFFFFFFFFFULL;
  uint64_t hi = (uint64_t)(a >> 64);
  uint64_t lo = (uint64_t)a;
  if (hi != 0xFFFFFFFFFFFFFFFEULL || lo != 0x0000000000000001ULL) return 1;

  // Test 2: 128-bit addition with carry
  unsigned __int128 b = (unsigned __int128)0xFFFFFFFFFFFFFFFFULL + 1;
  if ((uint64_t)(b >> 64) != 1 || (uint64_t)b != 0) return 2;

  // Test 3: addx carry propagation
  uint64_t carry = 0;
  uint64_t r = addx(0xFFFFFFFFFFFFFFFFULL, 1ULL, carry);
  if (r != 0 || carry != 1) return 3;

  // Test 4: subx borrow propagation
  uint64_t borrow = 0;
  r = subx(0ULL, 1ULL, borrow);
  if (r != 0xFFFFFFFFFFFFFFFFULL || borrow != 1) return 4;

  // Test 5: 128-bit shift
  unsigned __int128 c = (unsigned __int128)1 << 64;
  if ((uint64_t)(c >> 64) != 1 || (uint64_t)c != 0) return 5;

  // Test 6: field element multiply (small values)
  unsigned __int128 d = (unsigned __int128)0x7FFFFFFFFFFFFFFFULL * 0x7FFFFFFFFFFFFFFFULL;
  // Expected: 0x3FFFFFFFFFFFFFFF0000000000000001
  if ((uint64_t)(d >> 64) != 0x3FFFFFFFFFFFFFFFULL) return 6;
  if ((uint64_t)d != 0x0000000000000001ULL) return 6;

  return 0;
}

/**
 * Get the size of a pointer (for verifying 32-bit WASM).
 * JS can call this to sanity-check the WASM module loaded correctly.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_ptr_size() {
  return sizeof(void*);
}

}  // extern "C"
