/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_GOST_TLS_H
#define LIBPOGOST_GOST_TLS_H

#include <libpogost/types.h>

#define GOST_TLS_KEY_SIZE 32
#define GOST_TLS_IV_SIZE 8
#define GOST_TLS_MAC_SIZE 16

#define GOST_TLS13_KEY_SIZE 32
#define GOST_TLS13_IV_SIZE 16
#define GOST_TLS13_TAG_SIZE 16
#define GOST_TLS13_HASH_SIZE 32

void gost_hmac_streebog256(u8 out[32], const u8 *key, size_t key_len,
                           const u8 *data, size_t data_len);
int gost_kdf_tree_256(u8 *out, size_t out_len,
                      const u8 *key, size_t key_len,
                      const u8 *label, size_t label_len,
                      const u8 *seed, size_t seed_len);
int gost_tls_prf_256(u8 *out, size_t out_len,
                     const u8 *secret, size_t secret_len,
                     const char *label, const u8 *seed, size_t seed_len);
int gost_tls_tlstree_kuznyechik(u8 out[32], const u8 key[32],
                                const u8 seq[8]);
void kuznyechik_omac(u8 out[16], const u8 key[32],
                     const u8 *data, size_t data_len);
void kuznyechik_omac2(u8 out[16], const u8 key[32],
                      const u8 *a, size_t a_len,
                      const u8 *b, size_t b_len);
void kuznyechik_ctr_acpkm(u8 *out, const u8 *in, size_t len,
                          const u8 key[32], const u8 iv[8],
                          size_t section_size);
void kuznyechik_kexp15(u8 out[48], const u8 key[32],
                       const u8 mac_key[32], const u8 enc_key[32],
                       const u8 iv[8]);
int kuznyechik_kimp15(u8 key[32], const u8 in[48],
                       const u8 mac_key[32], const u8 enc_key[32],
                       const u8 iv[8]);

/* TLS 1.3 primitives (RFC 9058, RFC 9367) */
void gost_tls13_make_nonce(u8 out_nonce[16], const u8 iv[16], u64 seq);

int kuznyechik_mgm_encrypt(u8 *out, u8 tag[16], const u8 key[32],
                           const u8 nonce[16], const u8 *aad, size_t aad_len,
                           const u8 *in, size_t in_len);
int kuznyechik_mgm_decrypt(u8 *out, const u8 key[32],
                           const u8 nonce[16], const u8 *aad, size_t aad_len,
                           const u8 *in, size_t in_len, const u8 tag[16]);

int gost_tls13_tlstree_kuznyechik_mgm_l(u8 out[32], const u8 key[32], u64 seq);
int gost_tls13_tlstree_kuznyechik_mgm_s(u8 out[32], const u8 key[32], u64 seq);

int gost_tls13_hkdf_extract(u8 prk[32], const u8 *salt, size_t salt_len,
                            const u8 *ikm, size_t ikm_len);
int gost_tls13_hkdf_expand(u8 *okm, size_t okm_len, const u8 prk[32],
                           const u8 *info, size_t info_len);
int gost_tls13_hkdf_expand_label(u8 *okm, size_t okm_len, const u8 secret[32],
                                 const char *label,
                                 const u8 *context, size_t context_len);

#endif
