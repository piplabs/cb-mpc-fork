#include "tdh2.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <cbmpc/core/buf.h>
#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/secret_sharing.h>
#include <cbmpc/crypto/tdh2.h>
#include <cbmpc/ffi/cmem_adapter.h>

using namespace coinbase;
using namespace coinbase::crypto;
using namespace coinbase::crypto::tdh2;
using node_t = coinbase::crypto::ss::node_t;

// ── Public key lifecycle ────────────────────────────────────────────────────

void free_tdh2_public_key(tdh2_public_key_ref ref) {
  delete static_cast<public_key_t*>(ref.opaque);
}

int tdh2_public_key_to_bytes(tdh2_public_key_ref ref, cmem_t* out) {
  if (ref.opaque == nullptr || out == nullptr) return coinbase::error(E_BADARG);
  const auto* pk = static_cast<const public_key_t*>(ref.opaque);
  *out = coinbase::ffi::copy_to_cmem(pk->to_bin());
  return SUCCESS;
}

int tdh2_public_key_from_bytes(cmem_t bytes, tdh2_public_key_ref* out) {
  if (out == nullptr) return coinbase::error(E_BADARG);
  auto* pk = new public_key_t();
  error_t rv = pk->from_bin(coinbase::ffi::view(bytes));
  if (rv) {
    delete pk;
    return rv;
  }
  out->opaque = pk;
  return SUCCESS;
}

int tdh2_public_key_from_point(cmem_t point_cmem, tdh2_public_key_ref* out) {
  if (out == nullptr) return coinbase::error(E_BADARG);
  ecc_point_t Q;
  error_t rv = coinbase::deser(coinbase::ffi::view(point_cmem), Q);
  if (rv) return rv;
  // public_key_t(Q) constructor derives Gamma automatically.
  out->opaque = new public_key_t(Q);
  return SUCCESS;
}

// ── Encryption / verification ───────────────────────────────────────────────

int tdh2_encrypt(tdh2_public_key_ref pub_key, cmem_t plain, cmem_t label, cmem_t* ciphertext_out) {
  if (pub_key.opaque == nullptr || ciphertext_out == nullptr) return coinbase::error(E_BADARG);
  const auto* pk = static_cast<const public_key_t*>(pub_key.opaque);
  if (!pk->valid()) return coinbase::error(E_CRYPTO, "invalid public key");
  ciphertext_t ct = pk->encrypt(coinbase::ffi::view(plain), coinbase::ffi::view(label));
  *ciphertext_out = coinbase::ffi::copy_to_cmem(coinbase::convert(ct));
  return SUCCESS;
}

int tdh2_verify(tdh2_public_key_ref pub_key, cmem_t ciphertext, cmem_t label) {
  if (pub_key.opaque == nullptr) return coinbase::error(E_BADARG);
  const auto* pk = static_cast<const public_key_t*>(pub_key.opaque);
  ciphertext_t ct;
  error_t rv = coinbase::convert(ct, coinbase::ffi::view(ciphertext));
  if (rv) return rv;
  // L is not included in the serialized ciphertext; restore it from the
  // caller-supplied label so that ciphertext_t::verify's label check passes.
  ct.L = coinbase::ffi::view(label);
  return ct.verify(*pk, coinbase::ffi::view(label));
}

// ── Per-party partial decryption ────────────────────────────────────────────

int tdh2_partial_decrypt(int pid, cmem_t share_scalar, tdh2_public_key_ref pub_key, cmem_t ciphertext,
                          cmem_t label, cmem_t* partial_decryption_out) {
  if (pub_key.opaque == nullptr || partial_decryption_out == nullptr) return coinbase::error(E_BADARG);
  const auto* pk = static_cast<const public_key_t*>(pub_key.opaque);

  private_share_t ps;
  ps.pid = pid;
  ps.x = bn_t::from_bin(coinbase::ffi::view(share_scalar));
  ps.pub_key = *pk;

  ciphertext_t ct;
  error_t rv = coinbase::convert(ct, coinbase::ffi::view(ciphertext));
  if (rv) return rv;
  // L is not included in the serialized ciphertext; restore it from the
  // caller-supplied label so that ciphertext_t::verify's label check passes.
  ct.L = coinbase::ffi::view(label);

  partial_decryption_t pd;
  rv = ps.decrypt(ct, coinbase::ffi::view(label), pd);
  if (rv) return rv;

  *partial_decryption_out = coinbase::ffi::copy_to_cmem(coinbase::convert(pd));
  return SUCCESS;
}

// ── AC combining ────────────────────────────────────────────────────────────

int tdh2_combine_ac(crypto_ss_ac_ref* ac_ptr, tdh2_public_key_ref pub_key, cmems_t names, cmems_t pub_shares,
                    cmem_t ciphertext, cmem_t label, cmems_t pd_values, cmem_t* plain_out) {
  if (ac_ptr == nullptr || ac_ptr->opaque == nullptr) return coinbase::error(E_CRYPTO, "null ac pointer");
  if (pub_key.opaque == nullptr || plain_out == nullptr) return coinbase::error(E_BADARG);

  error_t rv = UNINITIALIZED_ERROR;
  const auto* pk = static_cast<const public_key_t*>(pub_key.opaque);

  std::vector<buf_t> name_bufs = coinbase::ffi::bufs_from_cmems(names);
  std::vector<buf_t> ps_bufs = coinbase::ffi::bufs_from_cmems(pub_shares);
  std::vector<buf_t> pd_bufs = coinbase::ffi::bufs_from_cmems(pd_values);

  if (name_bufs.size() != ps_bufs.size() || name_bufs.size() != pd_bufs.size())
    return coinbase::error(E_CRYPTO, "names, pub_shares, pd_values must have equal length");

  ss::ac_pub_shares_t pub_shares_map;
  ss::party_map_t<partial_decryption_t> pd_map;

  for (size_t i = 0; i < name_bufs.size(); i++) {
    std::string name((const char*)name_bufs[i].data(), name_bufs[i].size());

    ecc_point_t pt;
    rv = coinbase::deser(ps_bufs[i], pt);
    if (rv) return rv;
    pub_shares_map[name] = pt;

    partial_decryption_t pd;
    rv = coinbase::convert(pd, pd_bufs[i]);
    if (rv) return rv;
    pd_map[name] = pd;
  }

  ciphertext_t ct;
  rv = coinbase::convert(ct, coinbase::ffi::view(ciphertext));
  if (rv) return rv;
  // L is not included in the serialized ciphertext; restore it from the
  // caller-supplied label so that ciphertext_t::verify's label check passes.
  ct.L = coinbase::ffi::view(label);

  crypto::ss::ac_t* ac = static_cast<crypto::ss::ac_t*>(ac_ptr->opaque);

  buf_t plain;
  rv = combine(*ac, *pk, pub_shares_map, coinbase::ffi::view(label), pd_map, ct, plain);
  if (rv) return rv;

  *plain_out = coinbase::ffi::copy_to_cmem(plain);
  return SUCCESS;
}

