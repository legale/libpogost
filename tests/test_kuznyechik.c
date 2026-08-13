#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <libpogost/kuznyechik.h>
#include "../src/kuznyechik_internal.h"

/* Вектор из тестов Linux Crypto API. */
static const unsigned char key[KUZNYECHIK_KEY_SIZE] = {
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

static const unsigned char plaintext[KUZNYECHIK_BLOCK_SIZE] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
  0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
};

static const unsigned char ciphertext[KUZNYECHIK_BLOCK_SIZE] = {
  0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
  0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
};

static uint32_t random_word(uint32_t *state)
{
  *state = *state * 1664525U + 1013904223U;
  return *state;
}

#if defined(LIBPOGOST_HAVE_KUZNYECHIK_SIMD)
/* Generic и SIMD должны совпадать на разных ключах и блоках. */
static int test_differential(void)
{
  struct kuznyechik_ctx generic;
  struct kuznyechik_ctx simd;
  unsigned char key[KUZNYECHIK_KEY_SIZE];
  unsigned char input[KUZNYECHIK_BLOCK_SIZE];
  unsigned char generic_out[KUZNYECHIK_BLOCK_SIZE];
  unsigned char simd_out[KUZNYECHIK_BLOCK_SIZE];
  unsigned char recovered[KUZNYECHIK_BLOCK_SIZE];
  uint32_t state = 1;
  unsigned int i;
  unsigned int j;

  for (i = 0; i < 256; i++) {
    for (j = 0; j < sizeof(key); j++)
      key[j] = random_word(&state);
    for (j = 0; j < sizeof(input); j++)
      input[j] = random_word(&state);
    if (kuznyechik_setkey(&generic, key) ||
        kuznyechik_simd_setkey(&simd, key))
      return 1;
    kuznyechik_encrypt(&generic, generic_out, input);
    kuznyechik_simd_encrypt(&simd, simd_out, input);
    if (memcmp(generic_out, simd_out, sizeof(generic_out)))
      return 1;
    kuznyechik_simd_decrypt(&simd, recovered, simd_out);
    if (memcmp(recovered, input, sizeof(recovered)))
      return 1;
  }
  return 0;
}
#endif

int main(void)
{
  struct kuznyechik_ctx ctx;
  unsigned char out[KUZNYECHIK_BLOCK_SIZE];
  unsigned char recovered[KUZNYECHIK_BLOCK_SIZE];

  if (kuznyechik_setkey(&ctx, key))
    return 1;
  kuznyechik_encrypt(&ctx, out, plaintext);
  if (memcmp(out, ciphertext, sizeof(out)))
    return 1;
  kuznyechik_decrypt(&ctx, recovered, out);
  if (memcmp(recovered, plaintext, sizeof(recovered)))
    return 1;
  puts("kuznyechik generic: PASS");
#if defined(LIBPOGOST_HAVE_KUZNYECHIK_SIMD)
  if (kuznyechik_simd_setkey(&ctx, key))
    return 1;
  kuznyechik_simd_encrypt(&ctx, out, plaintext);
  if (memcmp(out, ciphertext, sizeof(out)))
    return 1;
  kuznyechik_simd_decrypt(&ctx, recovered, out);
  if (memcmp(recovered, plaintext, sizeof(recovered)))
    return 1;
  puts("kuznyechik simd: PASS");
  if (test_differential())
    return 1;
  puts("kuznyechik differential: PASS");
#endif
  return 0;
}
