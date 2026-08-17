/* test_vl_transport.c — host tests for transport/vl_chunk and transport/vl_line.
 *
 * Covers:
 *   - chunk: in-order, shuffled, duplicated, conflicting-duplicate, gaps,
 *     adversarial sequence numbers, wrong lengths, oversize configs, a
 *     1-byte MTU, buffer-too-small, and guard bytes around the state to prove
 *     nothing ever writes outside it
 *   - line: split writes, CRLF, LF, bare CR, whitespace padding, blank lines,
 *     an overlong line, and a line that never ends at all
 *   - end to end: a real minted blob pushed through both helpers and then
 *     through vl_verify()
 *
 * Host test. Not part of any device build; the only files allowed stdio.
 *
 * Build:
 *   cc -std=c99 -Wall -Wextra -Werror -Icore -Iinclude -Itests -Itransport \
 *      core/vl_*.c transport/vl_*.c tests/test_vl_transport.c \
 *      -o /tmp/test_vl_transport && /tmp/test_vl_transport
 *
 * (c) 2026 VectiVolt — Apache-2.0 License */

#include "vectilicense/vectilicense.h"

#include "vl_chunk.h"
#include "vl_line.h"

#include "vl_test_fixtures.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        if (cond) { g_pass++; }                                \
        else {                                                 \
            g_fail++;                                          \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);      \
            printf(__VA_ARGS__);                               \
            printf("\n");                                      \
        }                                                      \
    } while (0)

/* ========================================================================= */
/* chunk                                                                     */
/* ========================================================================= */

/* The state, fenced. Anything that writes outside vl_chunk_t trips a guard. */
struct guarded {
    uint8_t    front[64];
    vl_chunk_t c;
    uint8_t    back[64];
};

static void guard_init(struct guarded *g)
{
    memset(g->front, 0xA5, sizeof g->front);
    memset(g->back,  0x5A, sizeof g->back);
}

static int guards_intact(const struct guarded *g)
{
    size_t i;
    for (i = 0; i < sizeof g->front; i++) if (g->front[i] != 0xA5u) return 0;
    for (i = 0; i < sizeof g->back;  i++) if (g->back[i]  != 0x5Au) return 0;
    return 1;
}

/* Feed chunk `seq` of `msg` (length total, chunk size cs). */
static vl_status_t feed_nth(vl_chunk_t *c, const char *msg, size_t total,
                            size_t cs, uint32_t seq)
{
    size_t off  = (size_t)seq * cs;
    size_t want = total - off;
    if (want > cs) want = cs;
    return vl_chunk_feed(c, seq, msg + off, want);
}

static void test_chunk_basic(void)
{
    static const char msg[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";   /* 32 chars */
    const size_t total = sizeof msg - 1u;
    struct guarded g;
    char out[64];
    size_t n;
    uint32_t i;

    guard_init(&g);

    /* A never-reset state fails closed, it does not reassemble into zeros. */
    memset(&g.c, 0, sizeof g.c);
    CHECK(vl_chunk_feed(&g.c, 0, msg, 8) == VL_ERR_INVALID_ARG, "feed before reset");
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_ERR_INVALID_ARG,
          "complete before reset");

    CHECK(vl_chunk_reset(&g.c, 8, total) == VL_OK, "reset 8/32");
    CHECK(g.c.expect == 4u, "4 chunks expected, got %u", (unsigned)g.c.expect);

    /* In order. */
    for (i = 0; i < 4u; i++) {
        CHECK(feed_nth(&g.c, msg, total, 8, i) == VL_OK, "feed %u", (unsigned)i);
        if (i < 3u)
            CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_ERR_NOT_FOUND,
                  "incomplete after %u", (unsigned)i);
    }
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_OK, "complete");
    CHECK(n == total, "out_len %u", (unsigned)n);
    CHECK(strcmp(out, msg) == 0, "reassembled: '%s'", out);
    CHECK(out[total] == '\0', "NUL terminated");

    /* Reset really discards. */
    CHECK(vl_chunk_reset(&g.c, 8, total) == VL_OK, "re-reset");
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_ERR_NOT_FOUND,
          "reset discards prior chunks");
    CHECK(n == 0u, "out_len zeroed on failure");

    CHECK(guards_intact(&g), "guard bytes intact");
}

static void test_chunk_shuffled_and_dupes(void)
{
    static const char msg[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    const size_t total = sizeof msg - 1u;
    static const uint32_t order[] = { 3, 1, 3, 0, 1, 2, 0 };   /* shuffled + dupes */
    struct guarded g;
    char out[64];
    size_t n, k;

    guard_init(&g);
    CHECK(vl_chunk_reset(&g.c, 8, total) == VL_OK, "reset");

    for (k = 0; k < sizeof order / sizeof order[0]; k++)
        CHECK(feed_nth(&g.c, msg, total, 8, order[k]) == VL_OK,
              "shuffled/dup feed seq=%u", (unsigned)order[k]);

    CHECK(g.c.have == 4u, "duplicates counted once: have=%u", (unsigned)g.c.have);
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_OK, "complete out of order");
    CHECK(strcmp(out, msg) == 0, "reassembled out of order: '%s'", out);

    /* A duplicate that disagrees is rejected and does NOT corrupt the copy
     * already held. */
    CHECK(vl_chunk_feed(&g.c, 1, "XXXXXXXX", 8) == VL_ERR_BAD_FORMAT,
          "conflicting duplicate rejected");
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_OK, "still complete");
    CHECK(strcmp(out, msg) == 0, "held copy preserved: '%s'", out);

    CHECK(guards_intact(&g), "guard bytes intact");
}

static void test_chunk_gaps(void)
{
    static const char msg[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    const size_t total = sizeof msg - 1u;
    struct guarded g;
    char out[64];
    size_t n;

    guard_init(&g);
    CHECK(vl_chunk_reset(&g.c, 8, total) == VL_OK, "reset");

    /* Everything but chunk 2, plus chunk 0 three more times: the right NUMBER
     * of frames must not be mistaken for the right COVERAGE. */
    CHECK(feed_nth(&g.c, msg, total, 8, 0) == VL_OK, "seq 0");
    CHECK(feed_nth(&g.c, msg, total, 8, 1) == VL_OK, "seq 1");
    CHECK(feed_nth(&g.c, msg, total, 8, 3) == VL_OK, "seq 3");
    CHECK(feed_nth(&g.c, msg, total, 8, 0) == VL_OK, "seq 0 again");
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_ERR_NOT_FOUND,
          "gap is not complete");

    CHECK(feed_nth(&g.c, msg, total, 8, 2) == VL_OK, "late seq 2");
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_OK, "complete after gap filled");
    CHECK(strcmp(out, msg) == 0, "reassembled after gap: '%s'", out);

    CHECK(guards_intact(&g), "guard bytes intact");
}

static void test_chunk_adversarial(void)
{
    static const char msg[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    const size_t total = sizeof msg - 1u;
    static const uint8_t big[512] = { 0 };
    struct guarded g;
    char out[64];
    size_t n;

    guard_init(&g);
    CHECK(vl_chunk_reset(&g.c, 8, total) == VL_OK, "reset");

    /* Sequence numbers past the end, including the ones that would overflow
     * seq * chunk_size if they were not bounded first. */
    CHECK(vl_chunk_feed(&g.c, 4, msg, 8) == VL_ERR_BAD_FORMAT, "seq == expect");
    CHECK(vl_chunk_feed(&g.c, 5, msg, 8) == VL_ERR_BAD_FORMAT, "seq > expect");
    CHECK(vl_chunk_feed(&g.c, 0x1FFFFFFFu, msg, 8) == VL_ERR_BAD_FORMAT, "huge seq");
    CHECK(vl_chunk_feed(&g.c, 0xFFFFFFFFu, msg, 8) == VL_ERR_BAD_FORMAT, "seq = UINT32_MAX");
    CHECK(g.c.have == 0u, "rejected seqs stored nothing");

    /* Wrong lengths for a valid seq. */
    CHECK(vl_chunk_feed(&g.c, 0, msg, 7)   == VL_ERR_BAD_FORMAT, "short chunk");
    CHECK(vl_chunk_feed(&g.c, 0, msg, 9)   == VL_ERR_BAD_FORMAT, "long chunk");
    CHECK(vl_chunk_feed(&g.c, 0, big, 512) == VL_ERR_BAD_FORMAT, "oversize chunk");
    CHECK(vl_chunk_feed(&g.c, 0, msg, 0)   == VL_ERR_BAD_FORMAT, "empty chunk");
    CHECK(vl_chunk_feed(&g.c, 0, NULL, 8)  == VL_ERR_INVALID_ARG, "NULL data");
    CHECK(g.c.have == 0u, "bad lengths stored nothing");

    /* NULL states. */
    CHECK(vl_chunk_reset(NULL, 8, 32) == VL_ERR_INVALID_ARG, "reset NULL");
    CHECK(vl_chunk_feed(NULL, 0, msg, 8) == VL_ERR_INVALID_ARG, "feed NULL");
    CHECK(vl_chunk_complete(NULL, out, sizeof out, &n) == VL_ERR_INVALID_ARG, "complete NULL");
    CHECK(vl_chunk_complete(&g.c, NULL, sizeof out, &n) == VL_ERR_INVALID_ARG, "complete NULL out");
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, NULL) == VL_ERR_INVALID_ARG, "complete NULL len");

    /* Bad configurations, and each one leaves the state unusable. */
    CHECK(vl_chunk_reset(&g.c, 0, 32) == VL_ERR_INVALID_ARG, "zero chunk size");
    CHECK(vl_chunk_feed(&g.c, 0, msg, 8) == VL_ERR_INVALID_ARG, "disarmed after bad reset");
    CHECK(vl_chunk_reset(&g.c, 8, 0) == VL_ERR_INVALID_ARG, "zero total");
    CHECK(vl_chunk_reset(&g.c, 8, VL_CHUNK_MAX_LEN + 1u) == VL_ERR_INVALID_ARG, "total too big");
    CHECK(vl_chunk_feed(&g.c, 0, msg, 8) == VL_ERR_INVALID_ARG, "disarmed after oversize reset");
    CHECK(vl_chunk_reset(&g.c, 8, VL_CHUNK_MAX_LEN) == VL_OK, "total == max is fine");

    /* REGRESSION: chunk_size is a size_t argument stored in a uint32_t field.
     * It used to be validated BEFORE the cast while `expect` was computed from
     * the untruncated value, so on a 64-bit host reset(&c, 1<<32, 160) returned
     * VL_OK with chunk_size == 0 -- the one value the "zero chunk size" check
     * above exists to refuse -- and reset(&c, (1<<32)+1, 160) armed a state
     * that reported a fully reassembled 160-byte message after a single byte
     * was fed. Both must be refused, and refusal must leave the state disarmed. */
#if SIZE_MAX > 0xFFFFFFFFu
    CHECK(vl_chunk_reset(&g.c, (size_t)1u << 32, 32) == VL_ERR_INVALID_ARG,
          "chunk_size 2^32 refused (was VL_OK with chunk_size=%u)",
          (unsigned)g.c.chunk_size);
    CHECK(g.c.armed == 0u, "disarmed after 2^32 reset");
    CHECK(vl_chunk_reset(&g.c, ((size_t)1u << 32) + 1u, 32) == VL_ERR_INVALID_ARG,
          "chunk_size 2^32+1 refused");
    CHECK(vl_chunk_feed(&g.c, 0, msg, 1) == VL_ERR_INVALID_ARG,
          "one byte cannot complete a 32-byte message");
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_ERR_INVALID_ARG,
          "disarmed after 2^32+1 reset");
#endif
    /* The largest chunk_size that survives the cast is still accepted, and the
     * ceiling division must not wrap while computing it. */
    CHECK(vl_chunk_reset(&g.c, 0xFFFFFFFFu, 32) == VL_OK, "chunk_size UINT32_MAX accepted");
    CHECK(g.c.chunk_size == 0xFFFFFFFFu, "...stored as passed");
    CHECK(g.c.expect == 1u, "...and means exactly one chunk, got %u",
          (unsigned)g.c.expect);

    CHECK(guards_intact(&g), "guard bytes intact");
}

static void test_chunk_edges(void)
{
    static const char msg[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    const size_t total = sizeof msg - 1u;
    struct guarded g;
    char out[64];
    size_t n;
    uint32_t i;

    guard_init(&g);

    /* Ragged tail: 32 bytes in 7s = 4 full chunks + 4 bytes. */
    CHECK(vl_chunk_reset(&g.c, 7, total) == VL_OK, "reset 7/32");
    CHECK(g.c.expect == 5u, "5 chunks, got %u", (unsigned)g.c.expect);
    CHECK(vl_chunk_feed(&g.c, 4, msg + 28, 7) == VL_ERR_BAD_FORMAT,
          "last chunk must be its real length, not padded");
    for (i = 0; i < 5u; i++)
        CHECK(feed_nth(&g.c, msg, total, 7, i) == VL_OK, "ragged feed %u", (unsigned)i);
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_OK, "ragged complete");
    CHECK(strcmp(out, msg) == 0, "ragged reassembly: '%s'", out);

    /* One chunk bigger than the whole message. */
    CHECK(vl_chunk_reset(&g.c, 1000, total) == VL_OK, "chunk > total");
    CHECK(g.c.expect == 1u, "single chunk");
    CHECK(vl_chunk_feed(&g.c, 0, msg, total) == VL_OK, "whole message in one");
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_OK, "single-chunk complete");
    CHECK(strcmp(out, msg) == 0, "single-chunk reassembly");

    /* 1-byte MTU: 32 chunks, exercises the bitmap across byte boundaries. */
    CHECK(vl_chunk_reset(&g.c, 1, total) == VL_OK, "1-byte MTU");
    CHECK(g.c.expect == total, "one chunk per byte");
    for (i = (uint32_t)total; i > 0u; i--)      /* backwards, for good measure */
        CHECK(feed_nth(&g.c, msg, total, 1, i - 1u) == VL_OK, "byte %u", (unsigned)(i - 1u));
    CHECK(vl_chunk_complete(&g.c, out, sizeof out, &n) == VL_OK, "1-byte MTU complete");
    CHECK(strcmp(out, msg) == 0, "1-byte MTU reassembly: '%s'", out);

    /* Output buffer must have room for the NUL as well. */
    CHECK(vl_chunk_complete(&g.c, out, total, &n) == VL_ERR_BUFFER_TOO_SMALL,
          "cap == total is too small");
    CHECK(n == 0u, "out_len zeroed on BUFFER_TOO_SMALL");
    CHECK(vl_chunk_complete(&g.c, out, total + 1u, &n) == VL_OK, "cap == total + 1 fits");
    CHECK(n == total, "exact-fit out_len");

    CHECK(guards_intact(&g), "guard bytes intact");
}

/* ========================================================================= */
/* line                                                                      */
/* ========================================================================= */

struct guarded_line {
    uint8_t   front[64];
    vl_line_t l;
    uint8_t   back[64];
};

static void gline_init(struct guarded_line *g)
{
    memset(g->front, 0xA5, sizeof g->front);
    memset(g->back,  0x5A, sizeof g->back);
    memset(&g->l, 0, sizeof g->l);
}

static int gline_intact(const struct guarded_line *g)
{
    size_t i;
    for (i = 0; i < sizeof g->front; i++) if (g->front[i] != 0xA5u) return 0;
    for (i = 0; i < sizeof g->back;  i++) if (g->back[i]  != 0x5Au) return 0;
    return 1;
}

/* Push a whole C string; return the status of the last byte. */
static vl_status_t push_str(vl_line_t *l, const char *s)
{
    vl_status_t st = VL_ERR_NOT_FOUND;
    while (*s != '\0') st = vl_line_push(l, *s++);
    return st;
}

/* Push a string and count how many complete lines came out. */
static int count_lines(vl_line_t *l, const char *s)
{
    int lines = 0;
    while (*s != '\0') if (vl_line_push(l, *s++) == VL_OK) lines++;
    return lines;
}

static void test_line_basic(void)
{
    struct guarded_line g;

    gline_init(&g);

    /* A zeroed struct is usable without an explicit reset. */
    CHECK(push_str(&g.l, "ABC\n") == VL_OK, "simple line");
    CHECK(strcmp(g.l.buf, "ABC") == 0, "line content '%s'", g.l.buf);
    CHECK(g.l.len == 3u, "line length %u", (unsigned)g.l.len);

    /* The next push starts a new line; the old one does not leak into it. */
    CHECK(push_str(&g.l, "DE\n") == VL_OK, "second line");
    CHECK(strcmp(g.l.buf, "DE") == 0, "second content '%s'", g.l.buf);

    /* Split writes: the same line arriving in four reads. */
    vl_line_reset(&g.l);
    CHECK(push_str(&g.l, "AB")  == VL_ERR_NOT_FOUND, "partial 1");
    CHECK(push_str(&g.l, "CD")  == VL_ERR_NOT_FOUND, "partial 2");
    CHECK(push_str(&g.l, "EF")  == VL_ERR_NOT_FOUND, "partial 3");
    CHECK(push_str(&g.l, "G\n") == VL_OK,            "split write completes");
    CHECK(strcmp(g.l.buf, "ABCDEFG") == 0, "split content '%s'", g.l.buf);

    /* Terminators. CRLF must yield ONE line, not two. */
    vl_line_reset(&g.l);
    CHECK(count_lines(&g.l, "one\r\ntwo\r\nthree\n") == 3, "CRLF yields one line each");
    CHECK(strcmp(g.l.buf, "three") == 0, "last CRLF line '%s'", g.l.buf);

    vl_line_reset(&g.l);
    CHECK(count_lines(&g.l, "bare\r") == 1, "bare CR terminates (terminal Enter)");
    CHECK(strcmp(g.l.buf, "bare") == 0, "bare CR content '%s'", g.l.buf);

    /* Blank and whitespace-only lines produce nothing. */
    vl_line_reset(&g.l);
    CHECK(count_lines(&g.l, "\n\r\n   \t\n\r\r\n") == 0, "blank lines ignored");

    /* Whitespace padding is stripped, '-' grouping is kept for vl_verify. */
    vl_line_reset(&g.l);
    CHECK(push_str(&g.l, "  \tAB-CD  \t\r") == VL_OK, "padded line");
    CHECK(strcmp(g.l.buf, "AB-CD") == 0, "padding stripped: '%s'", g.l.buf);
    CHECK(vl_line_push(&g.l, '\n') == VL_ERR_NOT_FOUND, "the LF of CRLF yields nothing");

    CHECK(gline_intact(&g), "guard bytes intact");
}

static void test_line_overflow(void)
{
    struct guarded_line g;
    size_t i;

    gline_init(&g);

    /* Exactly at the limit is fine. */
    for (i = 0; i < VL_LINE_MAX_LEN; i++)
        CHECK(vl_line_push(&g.l, 'X') == VL_ERR_NOT_FOUND || i == 0, "fill %u", (unsigned)i);
    CHECK(g.l.len == VL_LINE_MAX_LEN, "filled to the brim: %u", (unsigned)g.l.len);
    CHECK(vl_line_push(&g.l, '\n') == VL_OK, "max-length line accepted");
    CHECK(strlen(g.l.buf) == VL_LINE_MAX_LEN, "max-length content kept");

    /* One over: discarded, reported once at the terminator, then recovered. */
    vl_line_reset(&g.l);
    for (i = 0; i < VL_LINE_MAX_LEN + 50u; i++) vl_line_push(&g.l, 'Y');
    CHECK(vl_line_push(&g.l, '\n') == VL_ERR_BAD_FORMAT, "overlong line rejected");
    CHECK(push_str(&g.l, "OK\n") == VL_OK, "recovers after overflow");
    CHECK(strcmp(g.l.buf, "OK") == 0, "post-overflow content '%s'", g.l.buf);

    /* A line that never ends: 100k bytes, no terminator, no crash, no growth. */
    vl_line_reset(&g.l);
    for (i = 0; i < 100000u; i++) {
        vl_status_t st = vl_line_push(&g.l, (char)('A' + (int)(i % 26u)));
        if (st != VL_ERR_NOT_FOUND) { CHECK(0, "unterminated stream returned %d", (int)st); break; }
    }
    CHECK(g.l.len == 0u, "unterminated stream holds nothing");
    CHECK(gline_intact(&g), "guard bytes intact after 100k unterminated bytes");

    /* Reset mid-line abandons it. */
    vl_line_reset(&g.l);
    CHECK(push_str(&g.l, "PARTIAL") == VL_ERR_NOT_FOUND, "partial");
    vl_line_reset(&g.l);
    CHECK(push_str(&g.l, "AFTER\n") == VL_OK, "line after mid-line reset");
    CHECK(strcmp(g.l.buf, "AFTER") == 0, "reset dropped the partial: '%s'", g.l.buf);

    CHECK(vl_line_push(NULL, 'x') == VL_ERR_INVALID_ARG, "push NULL");
    vl_line_reset(NULL);          /* must not crash */

    CHECK(gline_intact(&g), "guard bytes intact");
}

/* ========================================================================= */
/* end to end: a real blob through both helpers, then vl_verify()            */
/* ========================================================================= */

/* Same hardware id segments gen_fixtures.py used to mint the fixtures. */
static vl_status_t e2e_read_segment(void *ctx, uint32_t idx,
                                    uint8_t *out, size_t cap, size_t *out_len)
{
    static const uint8_t s0[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11 };
    static const char    s1[]  = "vecti-test-board";
    (void)ctx;

    switch (idx) {
    case 0:
        if (cap < sizeof s0) return VL_ERR_BUFFER_TOO_SMALL;
        memcpy(out, s0, sizeof s0);
        *out_len = sizeof s0;
        return VL_OK;
    case 1:
        if (cap < sizeof s1 - 1u) return VL_ERR_BUFFER_TOO_SMALL;
        memcpy(out, s1, sizeof s1 - 1u);
        *out_len = sizeof s1 - 1u;
        return VL_OK;
    case 2:
        *out_len = 0u;
        return VL_OK;
    default:
        return VL_ERR_NO_MORE_SEGMENTS;
    }
}

static void test_end_to_end(void)
{
    static vl_pubkey_t keys[1];
    vl_config_t  cfg;
    vl_hal_t     hal;
    vl_license_t lic;
    vl_chunk_t   rx;
    vl_line_t    ln;
    char         blob[VL_BLOB_STR_BUF_LEN];
    size_t       n, i;
    uint32_t     seq;
    int          got_line = 0;

    keys[0].key_id = 7;
    memcpy(keys[0].key, FIX_PUBKEY, VL_PUBKEY_LEN);

    memset(&cfg, 0, sizeof cfg);
    cfg.keys      = keys;
    cfg.key_count = 1;
    cfg.family    = 0x02;

    memset(&hal, 0, sizeof hal);
    hal.read_id_segment = e2e_read_segment;

    /* --- over 8-byte CAN frames, delivered backwards --- */
    CHECK(vl_chunk_reset(&rx, 8, VL_BLOB_STR_LEN) == VL_OK, "e2e reset");
    CHECK(rx.expect == 20u, "160/8 = 20 frames, got %u", (unsigned)rx.expect);
    for (seq = rx.expect; seq > 0u; seq--)
        CHECK(vl_chunk_feed(&rx, seq - 1u, FIX_BLOB_PERPETUAL + (seq - 1u) * 8u, 8) == VL_OK,
              "e2e frame %u", (unsigned)(seq - 1u));

    CHECK(vl_chunk_complete(&rx, blob, sizeof blob, &n) == VL_OK, "e2e complete");
    CHECK(n == VL_BLOB_STR_LEN, "e2e length %u", (unsigned)n);
    CHECK(strcmp(blob, FIX_BLOB_PERPETUAL) == 0, "e2e blob matches the fixture");

    memset(&lic, 0, sizeof lic);
    CHECK(vl_verify(blob, &cfg, &hal, &lic) == VL_OK, "e2e chunked blob verifies");
    CHECK(lic.serial == 1001u, "e2e serial %u", (unsigned)lic.serial);
    CHECK((lic.checked & VL_CHECKED_SIGNATURE) != 0u, "e2e signature checked");

    /* --- over a UART, grouped in 8s with dashes and CRLF --- */
    memset(&ln, 0, sizeof ln);
    for (i = 0; i < VL_BLOB_STR_LEN; i++) {
        if (i != 0u && (i % 8u) == 0u) vl_line_push(&ln, '-');
        if (vl_line_push(&ln, FIX_BLOB_PERPETUAL[i]) == VL_OK) got_line = 1;
    }
    CHECK(got_line == 0, "no line before the terminator");
    vl_line_push(&ln, '\r');
    CHECK(ln.ready == 1u, "line ready at CR");

    memset(&lic, 0, sizeof lic);
    CHECK(vl_verify(ln.buf, &cfg, &hal, &lic) == VL_OK,
          "e2e dash-grouped line verifies (vl_verify ignores '-')");
    CHECK(lic.serial == 1001u, "e2e line serial %u", (unsigned)lic.serial);

    /* A blob one chunk short must never reach vl_verify() at all. */
    CHECK(vl_chunk_reset(&rx, 8, VL_BLOB_STR_LEN) == VL_OK, "e2e reset 2");
    for (seq = 0; seq < 19u; seq++)
        vl_chunk_feed(&rx, seq, FIX_BLOB_PERPETUAL + seq * 8u, 8);
    CHECK(vl_chunk_complete(&rx, blob, sizeof blob, &n) == VL_ERR_NOT_FOUND,
          "19 of 20 frames is not a licence");
}

int main(void)
{
    printf("%s — transport tests\n\n", vl_version_str());
    test_chunk_basic();
    test_chunk_shuffled_and_dupes();
    test_chunk_gaps();
    test_chunk_adversarial();
    test_chunk_edges();
    test_line_basic();
    test_line_overflow();
    test_end_to_end();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
