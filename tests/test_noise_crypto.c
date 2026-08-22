/* SPDX-License-Identifier: GPL-2.0 */
#include <libpogost/blake2s.h>
#include <libpogost/chacha20poly1305.h>
#include <libpogost/curve25519.h>
#include <libpogost/poly1305.h>

#include <stdio.h>
#include <string.h>

static int chk(const char *name, const u8 *a, const u8 *b, size_t n)
{
	if (!memcmp(a, b, n)) {
		printf("%s: PASS\n", name);
		return 1;
	}
	printf("%s: FAIL\n", name);
	return 0;
}

static int hex(u8 *out, size_t len, const char *s)
{
	size_t i;
	unsigned int v;

	for (i = 0; i < len; i++) {
		if (sscanf(s + i * 2, "%2x", &v) != 1)
			return 0;
		out[i] = v;
	}
	return 1;
}

int main(void)
{
	static const u8 alice_priv[32] = {
		0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
		0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a,
	};
	static const u8 bob_pub[32] = {
		0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
		0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f,
	};
	static const u8 poly_key[32] = {
		0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
		0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
	};
	static const u8 cp_key[32] = {
		0x4b,0x28,0x4b,0xa3,0x7b,0xbe,0xe9,0xf8,0x31,0x80,0x82,0xd7,0xd8,0xe8,0xb5,0xa1,
		0xe2,0x18,0x18,0x8a,0x9c,0xfa,0xa3,0x3d,0x25,0x71,0x3e,0x40,0xbc,0x54,0x7a,0x3e,
	};
	static const u8 cp_ad[8] = { 0x6a,0xe2,0xad,0x3f,0x88,0x39,0x5a,0x40 };
	static const u8 cp_expect[17] = {
		0xb7,0x1b,0xb0,0x73,0x59,0xb0,0x84,0xb2,0x6d,0x8e,0xab,0x94,0x31,0xa1,0xae,0xac,0x89,
	};
	static const u8 cp_msg[1] = { 0xa4 };
	static const char poly_msg[] = "Cryptographic Forum Research Group";
	u8 key[32], ad[23], msg[31], nonce[24], expect[64];
	u8 out[64], tmp[64], digest[32];
	struct pogost_poly1305_desc_ctx pc;
	unsigned int i;
	int ok = 1;

	hex(expect, 32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
	pogost_blake2s(NULL, 0, (const u8 *)"abc", 3, digest, 32);
	ok &= chk("blake2s", digest, expect, 32);

	hex(expect, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
	ok &= pogost_curve25519(out, alice_priv, bob_pub);
	ok &= chk("curve25519", out, expect, 32);

	hex(expect, 16, "a8061dc1305136c6c22b8baf0c0127a9");
	pogost_poly1305_init(&pc, poly_key);
	pogost_poly1305_update(&pc, (const u8 *)poly_msg, sizeof(poly_msg) - 1);
	pogost_poly1305_final(&pc, out);
	ok &= chk("poly1305", out, expect, 16);

	pogost_chacha20poly1305_encrypt(out, cp_msg, sizeof(cp_msg), cp_ad,
					 sizeof(cp_ad), 0xc4c4c628291f32d2ULL, cp_key);
	ok &= chk("chacha20poly1305", out, cp_expect, sizeof(cp_expect));
	ok &= pogost_chacha20poly1305_decrypt(tmp, out, sizeof(cp_expect), cp_ad,
					      sizeof(cp_ad), 0xc4c4c628291f32d2ULL, cp_key);
	ok &= chk("chacha20poly1305 decrypt", tmp, cp_msg, sizeof(cp_msg));
	out[sizeof(cp_expect) - 1] ^= 1;
	if (pogost_chacha20poly1305_decrypt(tmp, out, sizeof(cp_expect), cp_ad,
					   sizeof(cp_ad), 0xc4c4c628291f32d2ULL, cp_key))
		ok = 0;

	for (i = 0; i < sizeof(key); i++) key[i] = i * 3 + 1;
	for (i = 0; i < sizeof(ad); i++) ad[i] = i * 5 + 7;
	for (i = 0; i < sizeof(msg); i++) msg[i] = i * 7 + 11;
	for (i = 0; i < sizeof(nonce); i++) nonce[i] = i + 9;
	hex(expect, 47, "ef645b3439fa1f6c978f13f516ab4c8a88f36873d552164efbcbe9853f965a7f024ce1f62842d9d0b631a3c8eda404");
	pogost_xchacha20poly1305_encrypt(out, msg, sizeof(msg), ad, sizeof(ad), nonce, key);
	ok &= chk("xchacha20poly1305", out, expect, 47);
	ok &= pogost_xchacha20poly1305_decrypt(tmp, out, 47, ad, sizeof(ad), nonce, key);
	ok &= chk("xchacha20poly1305 decrypt", tmp, msg, sizeof(msg));
	out[3] ^= 1;
	if (pogost_xchacha20poly1305_decrypt(tmp, out, 47, ad, sizeof(ad), nonce, key))
		ok = 0;

	return ok ? 0 : 1;
}
