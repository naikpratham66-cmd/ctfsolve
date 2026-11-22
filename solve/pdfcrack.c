/* Fast cracker for PDF Standard security handler R=4 / V=4 (AESV2).
 * Verifies the /U entry with RC4 as required by ISO 32000-1 Alg. 5
 * (the handout's Python script wrongly used AES-ECB there).
 * Build: gcc -O3 -march=native -o pdfcrack pdfcrack.c
 * Usage: ./pdfcrack wordlist [owner]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------------- MD5 (public-domain style, compact) ---------------- */
typedef struct { uint32_t h[4]; uint64_t len; uint8_t buf[64]; } MD5_CTX;

static const uint32_t K[64] = {
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};

static const uint8_t S[64] = {
7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};

#define ROTL(x,c) (((x)<<(c))|((x)>>(32-(c))))

static void md5_block(uint32_t h[4], const uint8_t *p)
{
    uint32_t w[16];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1]<<8) |
               ((uint32_t)p[i*4+2]<<16) | ((uint32_t)p[i*4+3]<<24);
    uint32_t a=h[0], b=h[1], c=h[2], d=h[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;          g = (3*i + 5) & 15; }
        else             { f = c ^ (b | ~d);       g = (7*i) & 15; }
        uint32_t tmp = d;
        d = c; c = b;
        b = b + ROTL(a + f + K[i] + w[g], S[i]);
        a = tmp;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
}

static void md5_init(MD5_CTX *c)
{
    c->h[0]=0x67452301; c->h[1]=0xefcdab89;
    c->h[2]=0x98badcfe; c->h[3]=0x10325476; c->len=0;
}

static void md5_update(MD5_CTX *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    size_t have = c->len & 63;
    c->len += n;
    if (have) {
        size_t need = 64 - have;
        if (n < need) { memcpy(c->buf + have, p, n); return; }
        memcpy(c->buf + have, p, need); md5_block(c->h, c->buf);
        p += need; n -= need;
    }
    while (n >= 64) { md5_block(c->h, p); p += 64; n -= 64; }
    if (n) memcpy(c->buf, p, n);
}

static void md5_final(MD5_CTX *c, uint8_t out[16])
{
    uint64_t bits = c->len * 8;
    uint8_t pad[72]; size_t have = c->len & 63;
    size_t padlen = (have < 56) ? 56 - have : 120 - have;
    memset(pad, 0, padlen + 8);
    pad[0] = 0x80;
    for (int i = 0; i < 8; i++) pad[padlen + i] = (uint8_t)(bits >> (8*i));
    md5_update(c, pad, padlen + 8);
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(c->h[i]);
        out[i*4+1] = (uint8_t)(c->h[i] >> 8);
        out[i*4+2] = (uint8_t)(c->h[i] >> 16);
        out[i*4+3] = (uint8_t)(c->h[i] >> 24);
    }
}

static void md5_buf(const void *data, size_t n, uint8_t out[16])
{
    MD5_CTX c; md5_init(&c); md5_update(&c, data, n); md5_final(&c, out);
}

/* ---------------- RC4 ---------------- */
static void rc4(const uint8_t *key, size_t klen, const uint8_t *in, uint8_t *out, size_t n)
{
    uint8_t S[256]; uint8_t t;
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 255;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int i = 0; j = 0;
    for (size_t k = 0; k < n; k++) {
        i = (i + 1) & 255;
        j = (j + S[i]) & 255;
        t = S[i]; S[i] = S[j]; S[j] = t;
        out[k] = in[k] ^ S[(S[i] + S[j]) & 255];
    }
}

/* ---------------- PDF data ---------------- */
static const uint8_t PAD[32] = {
0x28,0xBF,0x4E,0x5E,0x4E,0x75,0x8A,0x41,0x64,0x00,0x4E,0x56,0xFF,0xFA,0x01,0x08,
0x2E,0x2E,0x00,0xB6,0xD0,0x68,0x3E,0x80,0x2F,0x0C,0xA9,0xFE,0x64,0x53,0x69,0x7A};

static uint8_t O_[32], U_[32], ID[16];
static uint8_t PACKED_P[4];
static uint8_t PADID_HASH[16];   /* md5(PAD || ID) */
static uint8_t CHECK_TARGET[16];

static int hex2bin(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v; if (sscanf(hex + 2*i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static void make_key(const uint8_t pw[32], uint8_t key[16])
{
    MD5_CTX c; uint8_t d[16];
    md5_init(&c);
    md5_update(&c, pw, 32);
    md5_update(&c, O_, 32);
    md5_update(&c, PACKED_P, 4);
    md5_update(&c, ID, 16);
    md5_final(&c, d);
    for (int i = 0; i < 50; i++) md5_buf(d, 16, d);
    memcpy(key, d, 16);
}

/* check candidate user password (already padded, 32 bytes) */
static int test_pw(const uint8_t pw[32])
{
    uint8_t key[16], x[16], k2[16];
    make_key(pw, key);
    rc4(key, 16, PADID_HASH, x, 16);
    for (int r = 1; r <= 19; r++) {
        for (int i = 0; i < 16; i++) k2[i] = key[i] ^ (uint8_t)r;
        rc4(k2, 16, x, x, 16);
    }
    return memcmp(x, CHECK_TARGET, 16) == 0;
}

static void pad_pw(const uint8_t *pw, size_t len, uint8_t out[32])
{
    if (len > 32) len = 32;
    memcpy(out, pw, len);
    memcpy(out + len, PAD, 32 - len);
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s wordlist [owner]\n", argv[0]); return 2; }
    if (!hex2bin("27840181c28b98ba1a9eb4b5ef5c4999e43dd07aba05242f508800c3db782a0b", O_, 32)) return 2;
    if (!hex2bin("b39ad45859f5c7650219aba741e30d4d0021446990b9e4114071a4d9104984c1", U_, 32)) return 2;
    if (!hex2bin("0c26a16505826d1ddd4d4297378a0601", ID, 16)) return 2;
    int32_t P = -1028; memcpy(PACKED_P, &P, 4);
    memcpy(CHECK_TARGET, U_, 16);

    { uint8_t tmp[48]; memcpy(tmp, PAD, 32); memcpy(tmp + 32, ID, 16); md5_buf(tmp, 48, PADID_HASH); }

    int do_owner = (argc > 2 && strcmp(argv[2], "owner") == 0);
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("wordlist"); return 2; }

    char line[512];
    long count = 0;
    uint8_t pw[32];
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
        if (!n) continue;
        count++;
        pad_pw((const uint8_t *)line, n, pw);
        if (test_pw(pw)) { printf("FOUND user password: %s (candidate %ld)\n", line, count); fflush(stdout); return 0; }
        if (do_owner) {
            /* Alg. 7: hash owner pw -> RC4 chain decrypt O -> user pw */
            uint8_t h[16], ok[16], up[32]; MD5_CTX c;
            md5_init(&c); md5_update(&c, pw, 32); md5_final(&c, h);
            for (int i = 0; i < 50; i++) md5_buf(h, 16, h);
            memcpy(ok, h, 16);
            memcpy(up, O_, 32);
            for (int r = 19; r >= 0; r--) {
                uint8_t k2[16];
                for (int i = 0; i < 16; i++) k2[i] = ok[i] ^ (uint8_t)r;
                rc4(k2, 16, up, up, 32);
            }
            if (test_pw(up)) { printf("FOUND owner password: %s (candidate %ld)\n", line, count); fflush(stdout); return 0; }
        }
    }
    printf("exhausted %ld candidates, no match\n", count);
    return 1;
}
