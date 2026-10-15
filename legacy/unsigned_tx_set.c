// unsigned_tx_set.c
//
// Парсер unsigned_tx_set v5.
// С PT-dump для отладки.

#include "unsigned_tx_set.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

extern void platform_log(const char *msg);
extern void monero_chacha20(const uint8_t *data, size_t length,
                            const uint8_t key[32], const uint8_t iv[8],
                            uint8_t *out);
extern void cn_slow_hash(const void *data, size_t length, char *hash,
                         int variant, int prehashed, uint64_t height);

// ---------------------------------------------------------------------------
// Хранилище последнего расшифрованного plaintext
// ---------------------------------------------------------------------------
static uint8_t *g_last_plain = NULL;
static size_t   g_last_plain_len = 0;

void uts_set_last_plain(uint8_t *p, size_t n) {
    g_last_plain = p;
    g_last_plain_len = n;
}

const uint8_t *uts_get_last_plain(size_t *out_len) {
    if (out_len) *out_len = g_last_plain_len;
    return g_last_plain;
}

// ---------------------------------------------------------------------------
// Логирование
// ---------------------------------------------------------------------------
static void uts_logf(const char *fmt, ...) {
    char buf[220];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    platform_log(buf);
}

#define UTS_FAIL(msg) do { uts_logf("uts: FAIL %s (pos=%u)", msg, (unsigned)r->pos); return false; } while (0)
#define UTS_CHECK(x, msg) do { if (!(x)) UTS_FAIL(msg); } while (0)

typedef struct { const uint8_t *data; size_t size; size_t pos; } dsl_reader_t;

static bool dsl_varint(dsl_reader_t *r, uint64_t *out) {
    uint64_t v = 0; int shift = 0;
    for (;;) {
        if (r->pos >= r->size) return false;
        uint8_t b = r->data[r->pos++];
        v |= ((uint64_t)(b & 0x7f)) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 63) return false;
    }
    *out = v; return true;
}
static bool dsl_bytes(dsl_reader_t *r, uint8_t *out, size_t n) {
    if (r->pos + n > r->size) return false;
    if (out) memcpy(out, r->data + r->pos, n);
    r->pos += n; return true;
}
static bool dsl_u8(dsl_reader_t *r, uint8_t *out) { return dsl_bytes(r, out, 1); }
static bool dsl_bool(dsl_reader_t *r, bool *out) { uint8_t b; if (!dsl_u8(r, &b)) return false; *out = (b != 0); return true; }
static bool dsl_u64_le(dsl_reader_t *r, uint64_t *out) {
    uint8_t b[8]; if (!dsl_bytes(r, b, 8)) return false;
    uint64_t v = 0; for (int i = 0; i < 8; i++) v |= ((uint64_t)b[i]) << (8 * i);
    *out = v; return true;
}
static bool dsl_key32(dsl_reader_t *r, uint8_t out[32]) { return dsl_bytes(r, out, 32); }
static bool dsl_ctkey(dsl_reader_t *r, uts_ctkey_t *out) { return dsl_key32(r, out->dest) && dsl_key32(r, out->mask); }
static bool dsl_account_addr(dsl_reader_t *r, uts_account_public_address_t *out) {
    return dsl_key32(r, out->spend_public_key) && dsl_key32(r, out->view_public_key);
}

// ---------------------------------------------------------------------------
// Диагностический hexdump
// ---------------------------------------------------------------------------
static void dump_region_hex(const char *label, dsl_reader_t *r, size_t from, size_t to) {
    if (to > r->size) to = r->size;
    if (from > to) from = to;
    uts_logf("uts: ===== %s hexdump [%zu..%zu) =====", label, from, to);
    for (size_t base = from; base < to; base += 16) {
        char buf[220];
        int n = snprintf(buf, sizeof(buf), "uts: [%5u] ", (unsigned)base);
        for (size_t i = 0; i < 16 && base + i < to; i++)
            n += snprintf(buf + n, sizeof(buf) - n, "%02x ", r->data[base + i]);
        n += snprintf(buf + n, sizeof(buf) - n, " | ");
        for (size_t i = 0; i < 16 && base + i < to; i++) {
            uint8_t c = r->data[base + i];
            n += snprintf(buf + n, sizeof(buf) - n, "%c",
                          (c >= 0x20 && c <= 0x7e) ? c : '.');
        }
        platform_log(buf);
    }
    uts_logf("uts: ===== end %s =====", label);
}

// ---------------------------------------------------------------------------
// tx_source_entry — ИСПРАВЛЕННАЯ ВЕРСИЯ
//
// Формат (из cryptonote_tx_utils.h + serialization/pair.h + container.h):
//   varint(n_outputs)
//   n_outputs × [
//       0x02                          ← begin_array(2) в pair.h
//       varint(global_index)          ← serialize_pair_element<uint64_t> = varint
//       ctkey(64)                     ← serialize_pair_element<ctkey> = blob
//   ]
//   uint64 real_output                ← FIELD(uint64_t) = 8 байт LE
//   real_out_tx_key(32)               ← FIELD = 32 байта
//   vector<public_key> additional     ← varint(count) + count×32 (ВСЕГДА!)
//   uint64 real_output_in_tx_index    ← FIELD = 8 байт LE
//   uint64 amount                     ← FIELD = 8 байт LE
//   bool rct                          ← FIELD = 1 байт
//   mask(32)                          ← FIELD = 32 байта
//   multisig_kLRki(128)               ← FIELD = 128 байт
// ---------------------------------------------------------------------------
static bool read_tx_source_entry(dsl_reader_t *r, uint32_t src_idx,
                                 uts_tx_source_entry_t *out)
{
    memset(out, 0, sizeof(*out));
    size_t src_start = r->pos;

    uts_logf("uts: src[%u] start pos=%zu", src_idx, r->pos);

    uint64_t n;
    UTS_CHECK(dsl_varint(r, &n), "src: n_outputs");
    if (n > UTS_MAX_RING_SIZE) return false;
    out->n_outputs = (uint32_t)n;
    uts_logf("uts: src[%u] n_outputs=%u", src_idx, out->n_outputs);

    for (uint32_t i = 0; i < out->n_outputs; i++) {
        uint8_t marker;
        UTS_CHECK(dsl_u8(r, &marker), "src: pair marker");
        if (marker != 0x02) {
            uts_logf("uts: src[%u] ring[%u] pair marker=0x%02x (expected 0x02)",
                     src_idx, i, marker);
            return false;
        }
        UTS_CHECK(dsl_varint(r, &out->outputs[i].global_index), "src: idx");
        UTS_CHECK(dsl_ctkey(r, &out->outputs[i].ctkey), "src: ctkey");
    }
    uts_logf("uts: src[%u] rings done pos=%zu", src_idx, r->pos);

    UTS_CHECK(dsl_u64_le(r, &out->real_output), "src: real_output");
    uts_logf("uts: src[%u] real_output=%llu pos=%zu",
             src_idx, (unsigned long long)out->real_output, r->pos);

    UTS_CHECK(dsl_key32(r, out->real_out_tx_key), "src: real_out_tx_key");

    // vector<public_key> additional_tx_keys — ВСЕГДА читаем
    UTS_CHECK(dsl_varint(r, &n), "src: n_additional_tx_keys");
    if (n > UTS_MAX_ADDITIONAL_TX_KEYS) {
        uts_logf("uts: src[%u] n_additional_tx_keys=%llu TOO BIG",
                 src_idx, (unsigned long long)n);
        return false;
    }
    out->n_additional_tx_keys = (uint32_t)n;
    for (uint32_t i = 0; i < out->n_additional_tx_keys; i++) {
        UTS_CHECK(dsl_key32(r, out->additional_tx_keys[i]),
                  "src: additional_tx_key");
    }
    uts_logf("uts: src[%u] n_additional_tx_keys=%u pos=%zu",
             src_idx, out->n_additional_tx_keys, r->pos);

    UTS_CHECK(dsl_u64_le(r, &out->real_output_in_tx_index), "src: idx_in_tx");
    uts_logf("uts: src[%u] real_out_in_tx_idx=%llu",
             src_idx, (unsigned long long)out->real_output_in_tx_index);

    UTS_CHECK(dsl_u64_le(r, &out->amount), "src: amount");
    uts_logf("uts: src[%u] amount=%llu",
             src_idx, (unsigned long long)out->amount);

    UTS_CHECK(dsl_bool(r, &out->rct), "src: rct");

    UTS_CHECK(dsl_key32(r, out->mask), "src: mask");

    UTS_CHECK(dsl_bytes(r, out->multisig_kLRki, 128), "src: kLRki");

    uts_logf("uts: src[%u] END pos=%zu (size=%zu)",
             src_idx, r->pos, r->pos - src_start);
    return true;
}

// ---------------------------------------------------------------------------
// tx_destination_entry
// ---------------------------------------------------------------------------
static bool read_tx_destination_entry(dsl_reader_t *r, const char *field_name,
                                      uint32_t idx, uts_tx_destination_entry_t *out)
{
    memset(out, 0, sizeof(*out));
    size_t start = r->pos;

    uint64_t orig_len;
    UTS_CHECK(dsl_varint(r, &orig_len), "dest: original_len");
    if (orig_len > UTS_MAX_ORIGINAL_LEN) {
        uts_logf("uts: %s[%u] orig_len=%llu TOO BIG",
                 field_name, idx, (unsigned long long)orig_len);
        return false;
    }
    out->original_len = (uint32_t)orig_len;
    if (orig_len > 0) {
        UTS_CHECK(dsl_bytes(r, (uint8_t*)out->original, (size_t)orig_len),
                  "dest: original");
        out->original[orig_len] = 0;
    }
    UTS_CHECK(dsl_varint(r, &out->amount), "dest: amount");
    UTS_CHECK(dsl_account_addr(r, &out->addr), "dest: addr");
    UTS_CHECK(dsl_bool(r, &out->is_subaddress), "dest: is_subaddress");
    UTS_CHECK(dsl_bool(r, &out->is_integrated), "dest: is_integrated");

    uts_logf("uts: %s[%u] orig_len=%u amount=%llu sub=%d int=%d size=%zu end=%zu",
             field_name, idx, (unsigned)out->original_len,
             (unsigned long long)out->amount,
             out->is_subaddress ? 1 : 0, out->is_integrated ? 1 : 0,
             r->pos - start, r->pos);
    if (out->original_len > 0) uts_logf("uts:   original='%s'", out->original);
    return true;
}

// ---------------------------------------------------------------------------
// Probe: поиск splitted_dsts после change_dts (может быть gap)
// ---------------------------------------------------------------------------
static bool probe_splitted_dsts(dsl_reader_t *r, size_t p, uint32_t *out_n) {
    dsl_reader_t t = { r->data, r->size, p };
    uint64_t n;
    if (!dsl_varint(&t, &n)) return false;
    if (n < 1 || n > 4) return false;

    for (uint32_t i = 0; i < n; i++) {
        uint64_t orig_len;
        if (!dsl_varint(&t, &orig_len)) return false;
        if (orig_len > UTS_MAX_ORIGINAL_LEN) return false;
        if (orig_len > 0) {
            if (t.pos + orig_len > t.size) return false;
            for (size_t j = 0; j < orig_len; j++) {
                uint8_t c = t.data[t.pos + j];
                if (c < 0x20 || c > 0x7e) return false;
            }
            t.pos += orig_len;
        }
        uint64_t amt;
        if (!dsl_varint(&t, &amt)) return false;
        if (amt > 0xFFFFFFFFFFFFULL) return false;
        if (t.pos + 64 > t.size) return false;
        t.pos += 64;
        if (t.pos + 2 > t.size) return false;
        uint8_t s = t.data[t.pos], ii = t.data[t.pos + 1];
        if (s > 1 || ii > 1) return false;
        t.pos += 2;
    }

    uint64_t nsel;
    if (!dsl_varint(&t, &nsel)) return false;
    if (nsel > 64) return false;
    uint64_t elen;
    if (!dsl_varint(&t, &elen)) return false;
    if (elen > 200) return false;

    *out_n = (uint32_t)n;
    return true;
}

// ---------------------------------------------------------------------------
// RCTConfig: 3 varint (VERSION_FIELD + 2 поля)
// ---------------------------------------------------------------------------
static bool read_rct_config(dsl_reader_t *r, uint32_t *out_type, uint32_t *out_bp) {
    size_t save = r->pos;
    {
        dsl_reader_t t = *r;
        uint64_t ver, ty, bp, peek;
        if (dsl_varint(&t, &ver) && ver == 0 &&
            dsl_varint(&t, &ty) && ty <= 4 &&
            dsl_varint(&t, &bp) && bp >= 1 && bp <= 4) {
            size_t after_bp = t.pos;
            if (dsl_varint(&t, &peek) && peek >= 1 && peek <= 4) {
                r->pos = after_bp;
                *out_type = (uint32_t)ty; *out_bp = (uint32_t)bp;
                return true;
            }
        }
    }
    r->pos = save;
    {
        dsl_reader_t t = *r;
        uint64_t ty, bp, peek;
        if (dsl_varint(&t, &ty) && ty <= 4 &&
            dsl_varint(&t, &bp) && bp <= 4) {
            size_t after_bp = t.pos;
            if (dsl_varint(&t, &peek) && peek >= 1 && peek <= 4) {
                r->pos = after_bp;
                *out_type = (uint32_t)ty; *out_bp = (uint32_t)bp;
                return true;
            }
        }
    }
    r->pos = save;
    return false;
}

// ---------------------------------------------------------------------------
// tx_construction_data
// ---------------------------------------------------------------------------
static bool read_tx_construction_data(dsl_reader_t *r,
                                      uts_tx_construction_data_t *out)
{
    memset(out, 0, sizeof(*out));
    uint64_t n;

    UTS_CHECK(dsl_varint(r, &n), "txcd: n_sources");
    if (n > UTS_MAX_SOURCES) return false;
    out->n_sources = (uint32_t)n;
    for (uint32_t i = 0; i < out->n_sources; i++) {
        if (!read_tx_source_entry(r, i, &out->sources[i])) return false;
    }

    UTS_CHECK(read_tx_destination_entry(r, "change", 0, &out->change_dts),
              "txcd: change_dts");

    // Поиск splitted_dsts
    size_t spl_pos = 0;
    uint32_t spl_n = 0;
    for (size_t p = r->pos; p < r->pos + 250 && p < r->size; p++) {
        if (probe_splitted_dsts(r, p, &spl_n)) { spl_pos = p; break; }
    }
    if (spl_pos == 0) { uts_logf("uts: splitted_dsts NOT FOUND"); return false; }
    uts_logf("uts: splitted_dsts at pos=%zu (gap=%zu)", spl_pos, spl_pos - r->pos);
    r->pos = spl_pos;

    UTS_CHECK(dsl_varint(r, &n), "txcd: n_splitted_dsts");
    if (n > UTS_MAX_DESTS) return false;
    out->n_splitted_dsts = (uint32_t)n;
    for (uint32_t i = 0; i < out->n_splitted_dsts; i++) {
        UTS_CHECK(read_tx_destination_entry(r, "split", i,
                                            &out->splitted_dsts[i]),
                  "txcd: split");
    }

    UTS_CHECK(dsl_varint(r, &n), "txcd: n_selected_transfers");
    if (n > UTS_MAX_SELECTED) return false;
    out->n_selected_transfers = (uint32_t)n;
    for (uint32_t i = 0; i < out->n_selected_transfers; i++) {
        uint64_t v;
        UTS_CHECK(dsl_varint(r, &v), "txcd: selected[i]");
        out->selected_transfers[i] = v;
    }

    UTS_CHECK(dsl_varint(r, &n), "txcd: extra_len");
    if (n > UTS_MAX_EXTRA) return false;
    out->extra_len = (uint32_t)n;
    if (out->extra_len > 0) {
        UTS_CHECK(dsl_bytes(r, out->extra, out->extra_len), "txcd: extra");
    }

    UTS_CHECK(dsl_u64_le(r, &out->unlock_time), "txcd: unlock_time");

    UTS_CHECK(dsl_u8(r, &out->construction_flags), "txcd: construction_flags");
    out->use_rct       = (out->construction_flags & 0x01) != 0;
    out->use_view_tags = (out->construction_flags & 0x02) != 0;

    UTS_CHECK(read_rct_config(r, &out->rct_config_type, &out->rct_config_bp),
              "txcd: rct_config");

    UTS_CHECK(dsl_varint(r, &n), "txcd: n_dests");
    if (n > UTS_MAX_DESTS) return false;
    out->n_dests = (uint32_t)n;
    for (uint32_t i = 0; i < out->n_dests; i++) {
        UTS_CHECK(read_tx_destination_entry(r, "dest", i, &out->dests[i]),
                  "txcd: dest");
    }

    UTS_CHECK(dsl_varint(r, &n), "txcd: subaddr_account");
    out->subaddr_account = (uint32_t)n;

    UTS_CHECK(dsl_varint(r, &n), "txcd: n_subaddr_indices");
    if (n > UTS_MAX_SUBADDR_INDICES) return false;
    out->n_subaddr_indices = (uint32_t)n;
    for (uint32_t i = 0; i < out->n_subaddr_indices; i++) {
        uint64_t v;
        UTS_CHECK(dsl_varint(r, &v), "txcd: subaddr_idx");
        out->subaddr_indices[i] = (uint32_t)v;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Корень
// ---------------------------------------------------------------------------
bool uts_parse_plain(const uint8_t *in, size_t in_len, unsigned_tx_set_t *out)
{
    memset(out, 0, sizeof(*out));

    // ============ PT DUMP ============
    uts_logf("uts: =============== PT DUMP START ===============");
    for (size_t off = 0; off < in_len; off += 32) {
        char buf[220];
        int p = snprintf(buf, sizeof(buf), "PT %04x: ", (unsigned)off);
        for (size_t i = 0; i < 32 && off + i < in_len; i++)
            p += snprintf(buf + p, sizeof(buf) - p, "%02x", in[off + i]);
        platform_log(buf);
    }
    uts_logf("uts: =============== PT DUMP END =================");
    // =================================

    dsl_reader_t r = { in, in_len, 0 };
    uint64_t version;
    if (!dsl_varint(&r, &version)) return false;
    uts_logf("uts: version=%llu", (unsigned long long)version);
    if (version != 2) return false;

    uint64_t n;
    if (!dsl_varint(&r, &n)) return false;
    if (n > UTS_MAX_TXES) return false;
    out->n_txes = (uint32_t)n;
    uts_logf("uts: n_txes=%u", out->n_txes);

    for (uint32_t i = 0; i < out->n_txes; i++) {
        if (!read_tx_construction_data(&r, &out->txes[i])) {
            uts_logf("uts: tx[%u] parse FAILED at pos=%zu", i, r.pos);
            return false;
        }
    }
    uts_logf("uts: PARSE OK, final pos=%zu, size=%zu", r.pos, r.size);
    return true;
}

// ---------------------------------------------------------------------------
// Расшифровка
// ---------------------------------------------------------------------------
static void derive_chacha_key_from_view_sk(const uint8_t view_sk[32],
                                           uint8_t key_out[32])
{
    cn_slow_hash(view_sk, 32, (char *)key_out, 0, 0, 0);
}

bool uts_parse_encrypted(const uint8_t *in, size_t in_len,
                         const uint8_t view_sk[32],
                         unsigned_tx_set_t *out)
{
    memset(out, 0, sizeof(*out));
    const size_t IV_LEN = 8, SIG_LEN = 64;
    if (in_len < IV_LEN + SIG_LEN + 1) return false;

    const uint8_t *iv = in;
    const uint8_t *ct = in + IV_LEN;
    size_t ct_len = in_len - IV_LEN - SIG_LEN;

    uint8_t key[32];
    derive_chacha_key_from_view_sk(view_sk, key);
    uint8_t *pt = (uint8_t *)malloc(ct_len);
    if (!pt) { memset(key, 0, sizeof(key)); return false; }
    monero_chacha20(ct, ct_len, key, iv, pt);
    memset(key, 0, sizeof(key));

    bool ok = uts_parse_plain(pt, ct_len, out);
    if (ok) {
        uts_set_last_plain(pt, ct_len);
    } else {
        memset(pt, 0, ct_len);
        free(pt);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Человекочитаемый дамп
// ---------------------------------------------------------------------------
static void hex_first8(const uint8_t *d, char *out) {
    for (int i = 0; i < 8; i++) sprintf(out + i*2, "%02x", d[i]);
    strcpy(out + 16, "..");
}

static void fmt_xmr(uint64_t amount, char *out, size_t cap) {
    snprintf(out, cap, "%llu.%012llu XMR (%llu piconero)",
             (unsigned long long)(amount / 1000000000000ULL),
             (unsigned long long)(amount % 1000000000000ULL),
             (unsigned long long)amount);
}

static void dump_dst(const char *tag, const uts_tx_destination_entry_t *d) {
    char xmr[80], sh[24], vh[24];
    fmt_xmr(d->amount, xmr, sizeof(xmr));
    hex_first8(d->addr.spend_public_key, sh);
    hex_first8(d->addr.view_public_key, vh);
    uts_logf("uts:   %s: %s", tag, xmr);
    uts_logf("uts:     sub=%d int=%d orig_len=%u",
             d->is_subaddress ? 1 : 0, d->is_integrated ? 1 : 0,
             d->original_len);
    uts_logf("uts:     addr.spend=%s", sh);
    uts_logf("uts:     addr.view =%s", vh);
    if (d->original_len > 0) uts_logf("uts:     original='%s'", d->original);
}

static void dump_src(const uts_tx_source_entry_t *s, uint32_t idx) {
    char xmr[80], tk[24], mk[24];
    fmt_xmr(s->amount, xmr, sizeof(xmr));
    hex_first8(s->real_out_tx_key, tk);
    hex_first8(s->mask, mk);
    uts_logf("uts:   src[%u]: %s", idx, xmr);
    uts_logf("uts:     ring_size=%u real_output=%llu idx_in_tx=%llu rct=%d",
             s->n_outputs,
             (unsigned long long)s->real_output,
             (unsigned long long)s->real_output_in_tx_index,
             s->rct ? 1 : 0);
    uts_logf("uts:     real_out_tx_key=%s", tk);
    uts_logf("uts:     mask=%s", mk);
    uts_logf("uts:     n_additional_tx_keys=%u", s->n_additional_tx_keys);
    for (uint32_t i = 0; i < s->n_outputs; i++) {
        char dh[24], mh[24];
        hex_first8(s->outputs[i].ctkey.dest, dh);
        hex_first8(s->outputs[i].ctkey.mask, mh);
        uts_logf("uts:     ring[%2u] idx=%-10llu dest=%s mask=%s",
                 i, (unsigned long long)s->outputs[i].global_index, dh, mh);
    }
}

void uts_dump(const unsigned_tx_set_t *s) {
    uts_logf("uts_dump: ============ TX SET: %u tx(es) ============", s->n_txes);
    for (uint32_t t = 0; t < s->n_txes; t++) {
        const uts_tx_construction_data_t *tx = &s->txes[t];
        uts_logf("uts_dump: --- tx[%u] ---", t);
        uts_logf("uts_dump: INPUTS: %u", tx->n_sources);
        for (uint32_t i = 0; i < tx->n_sources; i++)
            dump_src(&tx->sources[i], i);
        uts_logf("uts_dump: CHANGE:");
        dump_dst("change", &tx->change_dts);
        uts_logf("uts_dump: SPLITTED_DSTS: %u", tx->n_splitted_dsts);
        for (uint32_t i = 0; i < tx->n_splitted_dsts; i++) {
            char tag[16]; snprintf(tag, sizeof(tag), "split[%u]", i);
            dump_dst(tag, &tx->splitted_dsts[i]);
        }
        uts_logf("uts_dump: SELECTED: %u", tx->n_selected_transfers);
        for (uint32_t i = 0; i < tx->n_selected_transfers; i++)
            uts_logf("uts_dump:   [%u]=%llu", i,
                     (unsigned long long)tx->selected_transfers[i]);
        if (tx->extra_len > 0) {
            uts_logf("uts_dump: EXTRA: %u bytes", tx->extra_len);
            for (uint32_t off = 0; off < tx->extra_len; off += 32) {
                char buf[220];
                int p = snprintf(buf, sizeof(buf), "uts_dump:   [%03u] ", off);
                uint32_t chunk = tx->extra_len - off;
                if (chunk > 32) chunk = 32;
                for (uint32_t i = 0; i < chunk; i++)
                    p += snprintf(buf + p, sizeof(buf) - p, "%02x",
                                  tx->extra[off + i]);
                platform_log(buf);
            }
        }
        uts_logf("uts_dump: UNLOCK_TIME=%llu", (unsigned long long)tx->unlock_time);
        uts_logf("uts_dump: FLAGS=0x%02x (rct=%d vt=%d)",
                 tx->construction_flags, tx->use_rct, tx->use_view_tags);
        uts_logf("uts_dump: RCT={type=%u,bp=%u}",
                 tx->rct_config_type, tx->rct_config_bp);
        uts_logf("uts_dump: DESTS: %u", tx->n_dests);
        for (uint32_t i = 0; i < tx->n_dests; i++) {
            char tag[16]; snprintf(tag, sizeof(tag), "dest[%u]", i);
            dump_dst(tag, &tx->dests[i]);
        }
        uts_logf("uts_dump: SUBADDR_ACC=%u n_idx=%u",
                 tx->subaddr_account, tx->n_subaddr_indices);
    }
    uts_logf("uts_dump: ============================================");
}