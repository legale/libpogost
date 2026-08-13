/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_GOST_TLS_H
#define LIBPOGOST_GOST_TLS_H

#include <stddef.h>
#include <stdint.h>

#define GOST_TLS_KEY_SIZE 32
#define GOST_TLS_IV_SIZE 8
#define GOST_TLS_MAC_SIZE 16

void gost_hmac_streebog256(uint8_t out[32], const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len);
int gost_kdf_tree_256(uint8_t *out, size_t out_len,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *label, size_t label_len,
                      const uint8_t *seed, size_t seed_len);
int gost_tls_prf_256(uint8_t *out, size_t out_len,
                     const uint8_t *secret, size_t secret_len,
                     const char *label, const uint8_t *seed, size_t seed_len);
int gost_tls_tlstree_kuznyechik(uint8_t out[32], const uint8_t key[32],
                                const uint8_t seq[8]);
void kuznyechik_omac(uint8_t out[16], const uint8_t key[32],
                     const uint8_t *data, size_t data_len);
void kuznyechik_omac2(uint8_t out[16], const uint8_t key[32],
                      const uint8_t *a, size_t a_len,
                      const uint8_t *b, size_t b_len);
void kuznyechik_ctr_acpkm(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t key[32], const uint8_t iv[8],
                          size_t section_size);
void kuznyechik_kexp15(uint8_t out[48], const uint8_t key[32],
                       const uint8_t mac_key[32], const uint8_t enc_key[32],
                       const uint8_t iv[8]);
int kuznyechik_kimp15(uint8_t key[32], const uint8_t in[48],
                       const uint8_t mac_key[32], const uint8_t enc_key[32],
                       const uint8_t iv[8]);

#endif
