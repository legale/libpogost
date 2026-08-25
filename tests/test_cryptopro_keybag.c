#include "pfx_internal.h"

#include <stdio.h>
#include <string.h>

static const uint8_t pass_utf16le[] = {
  '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6', 0,
};

static const uint8_t salt[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t kdf_expected[32] = {
  0x99, 0xa5, 0xcb, 0xd1, 0x95, 0x79, 0x95, 0x9b,
  0xc3, 0x61, 0xad, 0x2b, 0x1b, 0xfd, 0x81, 0x8f,
  0x7b, 0x9e, 0x26, 0x71, 0xfb, 0xcc, 0xab, 0x03,
  0x15, 0xe2, 0x0a, 0xc4, 0xa0, 0x1e, 0x02, 0x01,
};

static const uint8_t ukm[8] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static const uint8_t wrap_expected[32] = {
  0x3e, 0xae, 0x7a, 0x87, 0xe6, 0x8a, 0xb6, 0xf2,
  0xb6, 0x35, 0x71, 0xa1, 0x5c, 0x31, 0x48, 0x46,
  0x90, 0xef, 0x98, 0x68, 0x79, 0x40, 0x3c, 0x58,
  0xa8, 0x0b, 0xfb, 0x6d, 0x0a, 0xb9, 0x17, 0xf5,
};

static const uint8_t mac_expected[4] = {
  0xcf, 0x2a, 0x3b, 0xe2,
};

static const uint8_t wrap64_expected[64] = {
  0x3e, 0xae, 0x7a, 0x87, 0xe6, 0x8a, 0xb6, 0xf2,
  0xb6, 0x35, 0x71, 0xa1, 0x5c, 0x31, 0x48, 0x46,
  0x90, 0xef, 0x98, 0x68, 0x79, 0x40, 0x3c, 0x58,
  0xa8, 0x0b, 0xfb, 0x6d, 0x0a, 0xb9, 0x17, 0xf5,
  0x8e, 0x17, 0x89, 0x22, 0x65, 0xf0, 0xff, 0x5b,
  0x6f, 0xe5, 0x3d, 0x9b, 0xe5, 0x25, 0x3f, 0xa4,
  0x99, 0x31, 0x3c, 0x53, 0xd1, 0x05, 0x2c, 0x47,
  0x94, 0x6d, 0xe3, 0x9d, 0x76, 0xd2, 0x52, 0x9b,
};

static const uint8_t mac64_expected[4] = {
  0x1f, 0xce, 0xa6, 0x86,
};

int main(void)
{
  uint8_t raw[64];
  uint8_t wrapped[64];
  uint8_t unwrapped[64];
  uint8_t mac[4];
  uint8_t mac2[4];
  uint8_t blob[37];
  uint8_t enc[sizeof(blob)];
  uint8_t dec[sizeof(blob)];
  uint8_t key[32];
  size_t i;

  if (cryptopro_keybag_kdf(key, pass_utf16le, sizeof(pass_utf16le),
                           salt, sizeof(salt), 2000) ||
      memcmp(key, kdf_expected, sizeof(key))) {
    fprintf(stderr, "cryptopro keybag kdf failed\n");
    return 1;
  }

  for (i = 0; i < sizeof(raw); i++) {
    raw[i] = i;
  }
  if (cryptopro_keybag_wrap(wrapped, mac, raw, 32, key,
                            ukm, sizeof(ukm), 1) ||
      memcmp(wrapped, wrap_expected, sizeof(wrap_expected)) ||
      memcmp(mac, mac_expected, sizeof(mac))) {
    fprintf(stderr, "cryptopro keybag wrap failed\n");
    return 1;
  }
  if (cryptopro_keybag_wrap(unwrapped, mac2, wrapped, 32, key,
                            ukm, sizeof(ukm), 0) ||
      memcmp(unwrapped, raw, 32) ||
      memcmp(mac2, mac_expected, sizeof(mac2))) {
    fprintf(stderr, "cryptopro keybag unwrap failed\n");
    return 1;
  }
  if (cryptopro_keybag_wrap(wrapped, mac, raw, sizeof(raw), key,
                            ukm, sizeof(ukm), 1) ||
      memcmp(wrapped, wrap64_expected, sizeof(wrap64_expected)) ||
      memcmp(mac, mac64_expected, sizeof(mac))) {
    fprintf(stderr, "cryptopro keybag wrap 512 failed\n");
    return 1;
  }
  if (cryptopro_keybag_wrap(unwrapped, mac2, wrapped, sizeof(wrapped), key,
                            ukm, sizeof(ukm), 0) ||
      memcmp(unwrapped, raw, sizeof(raw)) ||
      memcmp(mac2, mac64_expected, sizeof(mac2))) {
    fprintf(stderr, "cryptopro keybag unwrap 512 failed\n");
    return 1;
  }

  for (i = 0; i < sizeof(blob); i++) {
    blob[i] = i * 3;
  }
  if (cryptopro_keybag_blob_crypt(enc, blob, sizeof(blob), key,
                                  salt, sizeof(salt), 1) ||
      cryptopro_keybag_blob_crypt(dec, enc, sizeof(enc), key,
                                  salt, sizeof(salt), 0) ||
      memcmp(dec, blob, sizeof(blob))) {
    fprintf(stderr, "cryptopro keybag blob cfb failed\n");
    return 1;
  }

  puts("cryptopro keybag: ok");
  return 0;
}
