#ifndef POGOST_XOSHIRO256PP_H
#define POGOST_XOSHIRO256PP_H

#include <libpogost/types.h>

struct pogost_xoshiro256pp {
	u64 s[4];
};

static inline u64 pogost_xoshiro256pp_step(struct pogost_xoshiro256pp *s)
{
	u64 x = s->s[0] + s->s[3];
	u64 res = (x << 23 | x >> 41) + s->s[0];
	u64 t = s->s[1] << 17;

	s->s[2] ^= s->s[0];
	s->s[3] ^= s->s[1];
	s->s[1] ^= s->s[2];
	s->s[0] ^= s->s[3];
	s->s[2] ^= t;
	s->s[3] = s->s[3] << 45 | s->s[3] >> 19;
	return res;
}

u64 pogost_xoshiro256pp_next(struct pogost_xoshiro256pp *s);
void pogost_xoshiro256pp_seed(struct pogost_xoshiro256pp *s, const u64 seed[4]);

#endif
