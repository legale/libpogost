/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_PFX_H
#define LIBPOGOST_PFX_H

#include <libpogost/types.h>

#define GOST_PFX_MAC_SIZE 64
#define GOST_PFX_CP80_MAC_SIZE 4

/* pass_utf8 is fed to PBKDF2 as-is. */
int gost_pfx_gost89_encrypt(u8 *out, const u8 *in, size_t len,
                            const u8 *pass_utf8, size_t pass_len,
                            const u8 *salt, size_t salt_len,
                            u32 iter, const u8 iv[8]);

/* Расшифровать содержимое PFX тем же GOST 28147 CFB режимом. */
int gost_pfx_gost89_decrypt(u8 *out, const u8 *in, size_t len,
                            const u8 *pass_utf8, size_t pass_len,
                            const u8 *salt, size_t salt_len,
                            u32 iter, const u8 iv[8]);

/* data is DER-encoded AuthenticatedSafe, not the outer OCTET STRING. */
int gost_pfx_mac(u8 out[GOST_PFX_MAC_SIZE],
                 const u8 *data, size_t data_len,
                 const u8 *pass_utf8, size_t pass_len,
                 const u8 *salt, size_t salt_len, u32 iter);

/* OID 1.2.840.113549.1.12.1.80. Password must already be UTF-16LE. */
int gost_pfx_cp80_wrap(u8 *enc,
                       u8 mac[GOST_PFX_CP80_MAC_SIZE],
                       const u8 *raw_key, size_t key_len,
                       const u8 *pass_utf16le, size_t pass_len,
                       const u8 *salt, size_t salt_len, u32 iter,
                       const u8 ukm[8]);

/* Encrypt an already DER-encoded CryptoPro CPBlob bag value. */
int gost_pfx_cp80_encrypt(u8 *out, const u8 *blob, size_t blob_len,
                          const u8 *pass_utf16le, size_t pass_len,
                          const u8 *salt, size_t salt_len, u32 iter);

#endif
