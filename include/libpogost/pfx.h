/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_PFX_H
#define LIBPOGOST_PFX_H

#include <stddef.h>
#include <stdint.h>

#define GOST_PFX_MAC_SIZE 64

/* pass_utf8 is fed to PBKDF2 as-is. */
int gost_pfx_gost89_encrypt(uint8_t *out, const uint8_t *in, size_t len,
                            const uint8_t *pass_utf8, size_t pass_len,
                            const uint8_t *salt, size_t salt_len,
                            uint32_t iter, const uint8_t iv[8]);

/* data is DER-encoded AuthenticatedSafe, not the outer OCTET STRING. */
int gost_pfx_mac(uint8_t out[GOST_PFX_MAC_SIZE],
                 const uint8_t *data, size_t data_len,
                 const uint8_t *pass_utf8, size_t pass_len,
                 const uint8_t *salt, size_t salt_len, uint32_t iter);

/* OID 1.2.840.113549.1.12.1.80. Password must already be UTF-16LE. */
int gost_pfx_cp80_wrap(uint8_t *out, const uint8_t *raw_key, size_t key_len,
                       const uint8_t *pass_utf16le, size_t pass_len,
                       const uint8_t *salt, size_t salt_len, uint32_t iter,
                       const uint8_t *ukm, size_t ukm_len);

/* Encrypt an already DER-encoded CryptoPro CPBlob bag value. */
int gost_pfx_cp80_encrypt(uint8_t *out, const uint8_t *blob, size_t blob_len,
                          const uint8_t *pass_utf16le, size_t pass_len,
                          const uint8_t *salt, size_t salt_len, uint32_t iter);

#endif
