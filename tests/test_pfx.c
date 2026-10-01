#include <libpogost/pfx.h>

#include <stdio.h>
#include <string.h>

static const u8 mac_expected[64] = {
  0xea, 0x12, 0x0d, 0xdf, 0xa8, 0x15, 0x7c, 0xdb,
  0xd9, 0xd2, 0x0c, 0xe2, 0x78, 0x51, 0x1b, 0xcb,
  0xec, 0x55, 0x6c, 0xe7, 0xd9, 0x2f, 0x38, 0xad,
  0x2f, 0xdd, 0x1a, 0xdc, 0xa1, 0xb6, 0xca, 0x63,
  0xb2, 0xc6, 0x3f, 0xa7, 0xb2, 0xa9, 0x45, 0xbd,
  0xd9, 0x0f, 0xf7, 0xbf, 0x72, 0xa9, 0xd3, 0x04,
  0xb1, 0x89, 0xa1, 0xb0, 0x20, 0xeb, 0xdd, 0x80,
  0x38, 0xaf, 0x41, 0x5a, 0x49, 0xa6, 0x92, 0x94,
};

static const u8 cp80_pass[] = {
  '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6', 0,
};

static const u8 cp80_salt[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const u8 cp80_ukm[8] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static const u8 cp80_wrap_expected[32] = {
  0x3e, 0xae, 0x7a, 0x87, 0xe6, 0x8a, 0xb6, 0xf2,
  0xb6, 0x35, 0x71, 0xa1, 0x5c, 0x31, 0x48, 0x46,
  0x90, 0xef, 0x98, 0x68, 0x79, 0x40, 0x3c, 0x58,
  0xa8, 0x0b, 0xfb, 0x6d, 0x0a, 0xb9, 0x17, 0xf5,
};

static const u8 cp80_mac_expected[GOST_PFX_CP80_MAC_SIZE] = {
  0xcf, 0x2a, 0x3b, 0xe2,
};

static const u8 cp80_blob_expected[32] = {
  0x13, 0x86, 0x4c, 0xc2, 0xc7, 0xbc, 0x69, 0x4c,
  0x9e, 0x5c, 0x2c, 0xfa, 0x15, 0x60, 0xa5, 0x4d,
  0xb0, 0x98, 0x7d, 0x9b, 0x65, 0xb4, 0x71, 0x18,
  0x56, 0x96, 0x3f, 0x80, 0xc4, 0xae, 0x25, 0x02,
};

static const u8 gost89_expected[16] = {
  0x80, 0x55, 0x16, 0x13, 0x3a, 0x41, 0xfa, 0x28,
  0x20, 0x08, 0x5d, 0x7a, 0xd4, 0xef, 0xb9, 0x77,
};

int main(void)
{
  static const u8 pass[] = "password";
  static const u8 mac_salt[] = "salt";
  static const u8 pbe_salt[] = "saltsalt";
  static const u8 data[] = "authenticated safe";
  static const u8 iv[8] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  };
  u8 raw[32];
  u8 out[64];
  u8 cp80_mac[GOST_PFX_CP80_MAC_SIZE];
  size_t i;

  if (gost_pfx_mac(out, data, sizeof(data) - 1, pass, sizeof(pass) - 1,
                   mac_salt, sizeof(mac_salt) - 1, 2) ||
      memcmp(out, mac_expected, sizeof(mac_expected))) {
    fprintf(stderr, "pfx mac failed\n");
    return 1;
  }

  for (i = 0; i < 16; i++) {
    raw[i] = i;
  }
  if (gost_pfx_gost89_encrypt(out, raw, 16, pass, sizeof(pass) - 1,
                              pbe_salt, sizeof(pbe_salt) - 1, 2, iv) ||
      memcmp(out, gost89_expected, sizeof(gost89_expected))) {
    fprintf(stderr, "pfx gost89 encrypt failed\n");
    return 1;
  }

  for (i = 0; i < 32; i++) {
    raw[i] = i;
  }
  if (gost_pfx_cp80_wrap(out, cp80_mac, raw, 32,
                         cp80_pass, sizeof(cp80_pass),
                         cp80_salt, sizeof(cp80_salt), 2000, cp80_ukm) ||
      memcmp(out, cp80_wrap_expected, sizeof(cp80_wrap_expected)) ||
      memcmp(cp80_mac, cp80_mac_expected, sizeof(cp80_mac))) {
    fprintf(stderr, "pfx cp80 wrap failed\n");
    return 1;
  }
  if (gost_pfx_cp80_encrypt(out, raw, 32, cp80_pass, sizeof(cp80_pass),
                            cp80_salt, sizeof(cp80_salt), 2000) ||
      memcmp(out, cp80_blob_expected, sizeof(cp80_blob_expected))) {
    fprintf(stderr, "pfx cp80 encrypt failed\n");
    return 1;
  }

  {
    static const u8 rc2_pass16[] = { 0, '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6', 0, 0 };
    static const u8 rc2_salt[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    static const u8 rc2_in[23] = "Hello RC2-40 PBE test!!";
    static const u8 rc2_expected[24] = {
      0xe4, 0x7e, 0xb5, 0xa4, 0xdb, 0x33, 0x4c, 0x1a,
      0xcc, 0x38, 0x51, 0xd7, 0xf6, 0x60, 0xe1, 0x6e,
      0xe8, 0x70, 0x9a, 0x72, 0x71, 0x37, 0x1f, 0x6b
    };
    u8 rc2_enc[64];
    u8 rc2_dec[64];
    size_t rc2_enc_len = sizeof(rc2_enc);
    size_t rc2_dec_len = sizeof(rc2_dec);

    if (gost_pfx_rc2_40_pbe_encrypt(rc2_enc, &rc2_enc_len, rc2_in, sizeof(rc2_in),
                                   rc2_pass16, sizeof(rc2_pass16),
                                   rc2_salt, sizeof(rc2_salt), 2000) ||
        rc2_enc_len != sizeof(rc2_expected) ||
        memcmp(rc2_enc, rc2_expected, sizeof(rc2_expected))) {
      fprintf(stderr, "pfx rc2_40 encrypt failed\n");
      return 1;
    }
    if (gost_pfx_rc2_40_pbe_decrypt(rc2_dec, &rc2_dec_len, rc2_enc, rc2_enc_len,
                                   rc2_pass16, sizeof(rc2_pass16),
                                   rc2_salt, sizeof(rc2_salt), 2000) ||
        rc2_dec_len != sizeof(rc2_in) ||
        memcmp(rc2_dec, rc2_in, sizeof(rc2_in))) {
      fprintf(stderr, "pfx rc2_40 decrypt failed\n");
      return 1;
    }
  }

  puts("pfx: ok");
  return 0;

}
