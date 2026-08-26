/* Внутренние ключи и простые операции без зависимости от libc. */
#ifndef LIBPOGOST_KUZNYECHIK_INTERNAL_H
#define LIBPOGOST_KUZNYECHIK_INTERNAL_H

#include <libpogost/kuznyechik.h>

#define KUZNYECHIK_SUBKEYS_SIZE (KUZNYECHIK_BLOCK_SIZE * 10)

struct kuznyechik_state {
  /* Десять ключей для прямого и обратного прохода. */
  u8 key[KUZNYECHIK_SUBKEYS_SIZE];
  u8 dekey[KUZNYECHIK_SUBKEYS_SIZE];
};

static inline struct kuznyechik_state *kuznyechik_state(
    struct kuznyechik_ctx *ctx)
{
  /* Публичный контекст содержит только этот непрозрачный буфер. */
  return (struct kuznyechik_state *)ctx->opaque;
}

static inline const struct kuznyechik_state *kuznyechik_const_state(
    const struct kuznyechik_ctx *ctx)
{
  return (const struct kuznyechik_state *)ctx->opaque;
}

static inline void kuznyechik_copy(u8 *dst, const u8 *src,
                                  unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    dst[i] = src[i];
}

static inline void kuznyechik_xor(u8 *dst, const u8 *src,
                                 unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    dst[i] ^= src[i];
}

static inline void kuznyechik_xor_copy(u8 *dst, const u8 *src1,
                                      const u8 *src2, unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    dst[i] = src1[i] ^ src2[i];
}

int kuznyechik_generic_setkey(struct kuznyechik_ctx *ctx,
                             const u8 key[KUZNYECHIK_KEY_SIZE]);
void kuznyechik_generic_encrypt(const struct kuznyechik_ctx *ctx,
                               u8 out[KUZNYECHIK_BLOCK_SIZE],
                               const u8 in[KUZNYECHIK_BLOCK_SIZE]);
void kuznyechik_generic_decrypt(const struct kuznyechik_ctx *ctx,
                               u8 out[KUZNYECHIK_BLOCK_SIZE],
                               const u8 in[KUZNYECHIK_BLOCK_SIZE]);
int kuznyechik_simd_setkey(struct kuznyechik_ctx *ctx,
                          const u8 key[KUZNYECHIK_KEY_SIZE]);
void kuznyechik_simd_encrypt(const struct kuznyechik_ctx *ctx,
                            u8 out[KUZNYECHIK_BLOCK_SIZE],
                            const u8 in[KUZNYECHIK_BLOCK_SIZE]);
void kuznyechik_simd_decrypt(const struct kuznyechik_ctx *ctx,
                            u8 out[KUZNYECHIK_BLOCK_SIZE],
                            const u8 in[KUZNYECHIK_BLOCK_SIZE]);

#endif
