#include <libpogost/xoshiro256pp.h>

u64 pogost_xoshiro256pp_next(struct pogost_xoshiro256pp *s)
{
	return pogost_xoshiro256pp_step(s);
}

void pogost_xoshiro256pp_seed(struct pogost_xoshiro256pp *s, const u64 seed[4])
{
	s->s[0] = seed[0];
	s->s[1] = seed[1];
	s->s[2] = seed[2];
	s->s[3] = seed[3];

	if (!(s->s[0] | s->s[1] | s->s[2] | s->s[3]))
		s->s[0] = 1;
}
