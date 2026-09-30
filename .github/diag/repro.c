/*
 * Shape of OpenSSL 3.6.4 tls_parse_all_extensions()/tls_parse_extension()
 * (ssl/statem/extensions.c), without OpenSSL. Built with /O2 /Gs0 as
 * OpenSSL's VC-* configs do. Prints "ok" if parse_all() returns normally.
 */
#include <stdio.h>
#include <stddef.h>

typedef struct { const unsigned char *curr; size_t remaining; } PACKET;
typedef struct { PACKET data; int present; int parsed; unsigned type; size_t order; } RAW;
typedef struct { void *meths; size_t meths_count; } CUSTEXT;
typedef struct { char pad[0x88]; size_t meths_count; } CERT;
typedef struct CONN {
    char pad0[0x40];
    int server;
    char pad1[0x878 - 0x44];
    CERT *cert;
} CONN;
typedef int (*parser_fn)(CONN *, PACKET *, unsigned, void *, size_t);
typedef int (*final_fn)(CONN *, unsigned, int);
typedef struct {
    unsigned type; unsigned context;
    parser_fn parse_ctos, parse_stoc;
    final_fn final;
} DEF;

static int p_ok(CONN *s, PACKET *p, unsigned c, void *x, size_t i)
{ (void)s; (void)p; (void)c; (void)x; (void)i; return 1; }
static int f_ok(CONN *s, unsigned c, int present)
{ (void)s; (void)c; (void)present; return 1; }

static const DEF defs[29] = {
    {0, 1, p_ok, p_ok, f_ok}, {1, 1, p_ok, NULL, NULL}, {2, 3, NULL, p_ok, f_ok},
    {3, 1, p_ok, p_ok, NULL}, {4, 2, p_ok, p_ok, f_ok},
};

__declspec(noinline) int custom_parse(CONN *s, unsigned c, unsigned t,
    const unsigned char *d, size_t l, void *x, size_t i)
{ (void)s; (void)c; (void)t; (void)d; (void)l; (void)x; (void)i; return 1; }

__declspec(noinline) int relevant(CONN *s, unsigned ext, unsigned ctx)
{ (void)s; return (ext & ctx) != 0 || ext == 0; }

int parse_one(CONN *s, size_t idx, int context, RAW *exts, void *x, size_t chainidx)
{
    RAW *cur = &exts[idx];
    parser_fn parser = NULL;
    if (!cur->present) return 1;
    if (cur->parsed) return 1;
    cur->parsed = 1;
    if (idx < 29) {
        const DEF *d = &defs[idx];
        if (!relevant(s, d->context, context)) return 1;
        parser = s->server ? d->parse_ctos : d->parse_stoc;
        if (parser != NULL) return parser(s, &cur->data, context, x, chainidx);
    }
    return custom_parse(s, context, cur->type, cur->data.curr,
                        cur->data.remaining, x, chainidx);
}

int parse_all(CONN *s, int context, RAW *exts, void *x, size_t chainidx, int fin)
{
    size_t i, n = 29;
    const DEF *d;
    n += s->cert->meths_count;
    for (i = 0; i < n; i++)
        if (!parse_one(s, i, context, exts, x, chainidx))
            return 0;
    if (fin) {
        for (i = 0, d = defs; i < 29; i++, d++)
            if (d->final != NULL && (d->context & context) != 0
                && !d->final(s, context, exts[i].present))
                return 0;
    }
    return 1;
}

int main(void)
{
    static CERT cert;
    static CONN conn;
    static RAW exts[40];
    int r;
    conn.cert = &cert;
    conn.server = 1;
    for (int i = 0; i < 40; i++) exts[i].present = i & 1;
    r = parse_all(&conn, 1, exts, NULL, 0, 1);
    printf("ok %d\n", r);
    return r == 1 ? 0 : 2;
}
