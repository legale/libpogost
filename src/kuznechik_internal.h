/* Внутренние ключи и простые операции без зависимости от libc. */
#ifndef LIBPOGOST_KUZNECHIK_INTERNAL_H
#define LIBPOGOST_KUZNECHIK_INTERNAL_H

#include <libpogost/kuznechik.h>

#define KUZNECHIK_SUBKEYS_SIZE (KUZNECHIK_BLOCK_SIZE * 10)

struct kuznechik_state {
  /* Десять ключей для прямого и обратного прохода. */
  uint8_t key[KUZNECHIK_SUBKEYS_SIZE];
  uint8_t dekey[KUZNECHIK_SUBKEYS_SIZE];
};

static inline struct kuznechik_state *kuznechik_state(
    struct kuznechik_ctx *ctx)
{
  /* Публичный контекст содержит только этот непрозрачный буфер. */
  return (struct kuznechik_state *)ctx->opaque;
}

static inline const struct kuznechik_state *kuznechik_const_state(
    const struct kuznechik_ctx *ctx)
{
  return (const struct kuznechik_state *)ctx->opaque;
}

static inline void kuznechik_copy(uint8_t *dst, const uint8_t *src,
                                  unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    dst[i] = src[i];
}

static inline void kuznechik_xor(uint8_t *dst, const uint8_t *src,
                                 unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    dst[i] ^= src[i];
}

static inline void kuznechik_xor_copy(uint8_t *dst, const uint8_t *src1,
                                      const uint8_t *src2, unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    dst[i] = src1[i] ^ src2[i];
}

int kuznechik_generic_setkey(struct kuznechik_ctx *ctx,
                             const uint8_t key[KUZNECHIK_KEY_SIZE]);
void kuznechik_generic_encrypt(const struct kuznechik_ctx *ctx,
                               uint8_t out[KUZNECHIK_BLOCK_SIZE],
                               const uint8_t in[KUZNECHIK_BLOCK_SIZE]);
void kuznechik_generic_decrypt(const struct kuznechik_ctx *ctx,
                               uint8_t out[KUZNECHIK_BLOCK_SIZE],
                               const uint8_t in[KUZNECHIK_BLOCK_SIZE]);
int kuznechik_simd_setkey(struct kuznechik_ctx *ctx,
                          const uint8_t key[KUZNECHIK_KEY_SIZE]);
void kuznechik_simd_encrypt(const struct kuznechik_ctx *ctx,
                            uint8_t out[KUZNECHIK_BLOCK_SIZE],
                            const uint8_t in[KUZNECHIK_BLOCK_SIZE]);
void kuznechik_simd_decrypt(const struct kuznechik_ctx *ctx,
                            uint8_t out[KUZNECHIK_BLOCK_SIZE],
                            const uint8_t in[KUZNECHIK_BLOCK_SIZE]);

#endif
