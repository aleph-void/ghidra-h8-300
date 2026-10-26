/* Test program for the H8 module's real-code check: integer, 32/64-bit, floating-point, string,
 * stdio, stdlib and math code from newlib, a switch table, function pointers and varargs, so the
 * linked image holds a broad mix of compiler-generated H8 code.  -DSMALL (normal mode, 64 Kbytes)
 * uses newlib's integer-only iprintf and leaves out the floating-point part. */
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rec {
	char name[12];
	long key;
	float weight;
};

static int cmp_rec(const void *a, const void *b)
{
	const struct rec *x = a, *y = b;
	if (x->key != y->key)
		return x->key < y->key ? -1 : 1;
	return strcmp(x->name, y->name);
}

static uint32_t crc32_bitwise(const uint8_t *p, size_t n)
{
	uint32_t c = 0xffffffffu;
	while (n--) {
		c ^= *p++;
		for (int k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320u & -(c & 1));
	}
	return ~c;
}

static int classify(int c)
{
	switch (c) {
	case 'a': return 1;
	case 'b': return 7;
	case 'c': return 3;
	case 'd': return 11;
	case 'e': return 5;
	case 'f': return 13;
	case 'g': return 2;
	case 'h': return 17;
	default: return -1;
	}
}

static long sum_va(int n, ...)
{
	va_list ap;
	long s = 0;
	va_start(ap, n);
	while (n--)
		s += va_arg(ap, long);
	va_end(ap);
	return s;
}

static int64_t mix64(int64_t a, int64_t b)
{
	return a * b / 7 + (a % 13) - (b >> 3);
}

typedef long (*op_fn)(long, long);
static long op_add(long a, long b) { return a + b; }
static long op_mul(long a, long b) { return a * b; }
static long op_div(long a, long b) { return b ? a / b : 0; }

volatile unsigned char port_dr;

int main(void)
{
	static struct rec recs[] = {
		{"delta", 4, 1.5f}, {"alpha", 1, 2.25f}, {"echo", 5, 0.5f}, {"bravo", 2, 3.0f}, {"charlie", 3, 1.0f},
	};
	char buf[64];
	op_fn ops[] = {op_add, op_mul, op_div};
	long acc = 1;
	qsort(recs, sizeof recs / sizeof recs[0], sizeof recs[0], cmp_rec);
	for (unsigned i = 0; i < sizeof recs / sizeof recs[0]; i++) {
#ifdef SMALL
		sniprintf(buf, sizeof buf, "%s:%ld:%d", recs[i].name, recs[i].key, (int)recs[i].key * 3);
#else
		snprintf(buf, sizeof buf, "%s:%ld:%.2f", recs[i].name, recs[i].key, (double)recs[i].weight);
#endif
		puts(buf);
		acc = ops[i % 3](acc, recs[i].key + classify(recs[i].name[0]));
	}
#ifdef SMALL
	iprintf("%lu %ld %ld %ld\n", (unsigned long)crc32_bitwise((const uint8_t *)buf, strlen(buf)), acc,
		sum_va(4, 1L, 20L, 300L, 4000L), (long)mix64(123456789LL, -98765LL));
#else
	float f = 0;
	for (int i = 1; i < 20; i++)
		f += sqrtf((float)i) * sinf(i * 0.1f);
	printf("%lu %ld %ld %lld %d\n", (unsigned long)crc32_bitwise((const uint8_t *)buf, strlen(buf)), acc,
	       sum_va(4, 1L, 20L, 300L, 4000L), (long long)mix64(123456789LL, -98765LL), (int)(f * 1000));
#endif
	for (int i = 0; i < 8; i++)
		port_dr = (unsigned char)(port_dr ^ (1 << i));
	char *p = malloc(100);
	if (p) {
		memset(p, 'x', 99);
		p[99] = 0;
#ifdef SMALL
		iprintf("%d\n", (int)strlen(p));
#else
		printf("%d\n", (int)strlen(p));
#endif
		free(p);
	}
	return (int)(acc & 0x7f);
}
