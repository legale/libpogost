/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_GOST_TLS_H
#define LIBPOGOST_GOST_TLS_H

#include <libpogost/types.h>

#define GOST_TLS_KEY_SIZE 32
#define GOST_TLS_IV_SIZE 8
#define GOST_TLS_MAC_SIZE 16

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

#endif
