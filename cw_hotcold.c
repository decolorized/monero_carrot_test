// cw_hotcold.c — см. cw_hotcold.h
//
// Сверено с monero src/wallet/hot_cold.cpp, hot_cold_serialization.h,
// carrot_impl/tx_builder_outputs.cpp, carrot_impl/format_utils.cpp,
// carrot_core/output_set_finalization.cpp (fcmp++-beta-stressnet-v3).
#include "cw_hotcold.h"
#include "cw_crypto.h"
#include "cw_sal.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

void monero_chacha20(const uint8_t *data, size_t length, const uint8_t key[32],
                     const uint8_t iv[8], uint8_t *out);
void cn_slow_hash(const void *data, size_t length, char *hash, int variant, int prehashed, uint64_t height);

#define MAX_INPUTS   128
#define MAX_OUTPUTS  16
#define MAX_EXTRA    1060

static const char MAGIC_OUTPUTS[]   = "Monero output export";
static const char MAGIC_KEYIMAGES[] = "Monero key image export";
static const char MAGIC_UNSIGNED[]  = "Monero unsigned tx set";
static const char MAGIC_SIGNED[]    = "Monero signed tx set";

static const char DS_HC_NORMAL_ANCHOR[] = "Carrot Hot-cold normal janus anchor";
static const char DS_HC_SPECIAL_EPHEM[] = "Carrot Hot-cold special ephemeral privkey";
static const char DS_HC_DUMMY_PID[]     = "Carrot Hot-cold dummy encrypted payment id";
static const char DS_HC_RERAND[]        = "Carrot Hot-cold rerandomization scalar";
static const char DS_KI_PROOF[]         = "Carrot key image knowledge proof";

#define TAG_SIGNATURE 0x23
#define TAG_SAL       0x24

#define ERR(...) do { if (err) snprintf(err, err_len, __VA_ARGS__); goto fail; } while (0)

// ===========================================================================
// чтение / запись binary_archive
// ===========================================================================
typedef struct { const uint8_t *p; size_t n, pos; bool ok; } rd_t;

static const uint8_t *rd_bytes(rd_t *r, size_t k)
{
    if (!r->ok || r->n - r->pos < k) { r->ok = false; return NULL; }
    const uint8_t *q = r->p + r->pos;
    r->pos += k;
    return q;
}

static uint64_t rd_varint(rd_t *r)
{
    uint64_t v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        const uint8_t *b = rd_bytes(r, 1);
        if (!b) return 0;
        v |= (uint64_t)(*b & 0x7f) << shift;
        if (!(*b & 0x80)) {
            if (*b == 0 && shift > 0) { r->ok = false; return 0; }   // неканонический varint
            return v;
        }
    }
    r->ok = false;
    return 0;
}

static uint8_t rd_u8(rd_t *r)
{
    const uint8_t *b = rd_bytes(r, 1);
    return b ? *b : 0;
}

static uint64_t rd_u64le(rd_t *r)
{
    const uint8_t *b = rd_bytes(r, 8);
    uint64_t v = 0;
    if (b) for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
    return v;
}

typedef struct { uint8_t *p; size_t n, cap; bool ok; } wr_t;

static void wr_put(wr_t *w, const void *d, size_t k)
{
    if (!w->ok) return;
    if (w->n + k > w->cap) {
        size_t cap = w->cap ? w->cap : 1024;
        while (cap < w->n + k) cap *= 2;
        uint8_t *np = (uint8_t *)cw_malloc(cap);
        if (!np) { w->ok = false; return; }
        if (w->p) { memcpy(np, w->p, w->n); cw_wipe(w->p, w->n); cw_free(w->p); }
        w->p = np;
        w->cap = cap;
    }
    memcpy(w->p + w->n, d, k);
    w->n += k;
}

static void wr_u8(wr_t *w, uint8_t v) { wr_put(w, &v, 1); }

static void wr_varint(wr_t *w, uint64_t v)
{
    uint8_t b[10];
    size_t n = 0;
    while (v >= 0x80) { b[n++] = (uint8_t)(v | 0x80); v >>= 7; }
    b[n++] = (uint8_t)v;
    wr_put(w, b, n);
}

static void wr_free(wr_t *w)
{
    if (w->p) { cw_wipe(w->p, w->cap); cw_free(w->p); }
    w->p = NULL;
    w->n = w->cap = 0;
}

// ===========================================================================
// контейнер: magic || version || iv(8) || chacha20(pt) || sig(64)
// ===========================================================================
bool cw_wallet_init(cw_wallet_t *w, const uint8_t k_s[32], const uint8_t k_v[32])
{
    memset(w, 0, sizeof(*w));
    if (!cw_keys_init(&w->keys, k_s, k_v)) return false;
    w->kdf_rounds = 1;
    cn_slow_hash(k_v, 32, (char *)w->chacha_key, 0, 0, 0);
    return true;
}

int cw_detect_file(const uint8_t *data, size_t len, int *version_out)
{
    static const struct { const char *m; int kind; } tab[] = {
        { MAGIC_OUTPUTS, CW_FILE_OUTPUTS }, { MAGIC_KEYIMAGES, CW_FILE_KEYIMAGES },
        { MAGIC_UNSIGNED, CW_FILE_UNSIGNED }, { MAGIC_SIGNED, CW_FILE_SIGNED },
    };
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        size_t ml = strlen(tab[i].m);
        if (len > ml && memcmp(data, tab[i].m, ml) == 0) {
            if (version_out) *version_out = data[ml];
            return tab[i].kind;
        }
    }
    return CW_FILE_UNKNOWN;
}

static const char *magic_for(int kind)
{
    switch (kind) {
    case CW_FILE_OUTPUTS:   return MAGIC_OUTPUTS;
    case CW_FILE_KEYIMAGES: return MAGIC_KEYIMAGES;
    case CW_FILE_UNSIGNED:  return MAGIC_UNSIGNED;
    case CW_FILE_SIGNED:    return MAGIC_SIGNED;
    }
    return NULL;
}

bool cw_decrypt_file(const cw_wallet_t *w, const uint8_t *file, size_t len,
                     uint8_t **out, size_t *out_len, int *kind_out, int *version_out)
{
    int version = 0;
    int kind = cw_detect_file(file, len, &version);
    if (kind == CW_FILE_UNKNOWN) return false;
    size_t pre = strlen(magic_for(kind)) + 1;
    if (len < pre + 8 + 64) return false;
    const uint8_t *iv = file + pre;
    size_t ct_len = len - pre - 8 - 64;

    // подпись view-ключом над iv || ct
    uint8_t h[32];
    cw_keccak(iv, 8 + ct_len, h);
    if (!cw_check_signature(file + len - 64, h, w->keys.K_v)) return false;

    uint8_t *pt = (uint8_t *)cw_malloc(ct_len ? ct_len : 1);
    if (!pt) return false;
    monero_chacha20(iv + 8, ct_len, w->chacha_key, iv, pt);
    *out = pt;
    *out_len = ct_len;
    if (kind_out) *kind_out = kind;
    if (version_out) *version_out = version;
    return true;
}

static bool encrypt_file(const cw_wallet_t *w, int kind, uint8_t version,
                         const uint8_t *pt, size_t pt_len, uint8_t **out, size_t *out_len)
{
    const char *m = magic_for(kind);
    size_t ml = strlen(m);
    size_t total = ml + 1 + 8 + pt_len + 64;
    uint8_t *buf = (uint8_t *)cw_malloc(total);
    if (!buf) return false;
    memcpy(buf, m, ml);
    buf[ml] = version;
    uint8_t *iv = buf + ml + 1;
    cw_random(iv, 8);
    monero_chacha20(pt, pt_len, w->chacha_key, iv, iv + 8);
    uint8_t h[32];
    cw_keccak(iv, 8 + pt_len, h);
    cw_generate_signature(buf + total - 64, h, w->keys.K_v, w->keys.k_v);
    *out = buf;
    *out_len = total;
    return true;
}

// ===========================================================================
// экспортированные выходы (exported_transfer_details_variant)
// ===========================================================================
typedef struct {
    int ver;                    // 1 — до Carrot, 2 — Carrot
    // ver 1
    const uint8_t *pubkey, *tx_pubkey, *additional;
    uint64_t internal_idx, global_idx;
    uint8_t  pflags;
    size_t   n_additional;
    uint32_t major, minor;
    // ver 2
    uint64_t cflags, block_index;
    const uint8_t *first_ki, *pid, *anchor, *ss_De;
    // оба
    uint64_t amount;
} etd_t;

enum { PF_SPENT = 1 << 0, PF_FROZEN = 1 << 1, PF_RCT = 1 << 2 };
enum {
    CF_SPENT = 1 << 0, CF_SELFSEND = 1 << 3, CF_CHANGE = 1 << 4, CF_CARROT_ADDR = 1 << 5,
    CF_INTERNAL = 1 << 6, CF_COINBASE = 1 << 7, CF_HAS_PID = 1 << 8,
};

static bool parse_etd(rd_t *r, etd_t *e)
{
    memset(e, 0, sizeof(*e));
    e->ver = (int)rd_varint(r);
    if (e->ver == 1) {
        e->pubkey = rd_bytes(r, 32);
        e->internal_idx = rd_varint(r);
        e->global_idx = rd_varint(r);
        e->tx_pubkey = rd_bytes(r, 32);
        e->pflags = rd_u8(r);
        e->amount = rd_varint(r);
        e->n_additional = (size_t)rd_varint(r);
        if (e->n_additional > 4096) return false;
        e->additional = rd_bytes(r, 32 * e->n_additional);
        e->major = (uint32_t)rd_varint(r);
        e->minor = (uint32_t)rd_varint(r);
    } else if (e->ver == 2) {
        e->cflags = rd_varint(r);
        if (e->cflags & CF_COINBASE) e->block_index = rd_u64le(r);
        else e->first_ki = rd_bytes(r, 32);
        if (e->cflags & CF_HAS_PID) {
            e->pid = rd_bytes(r, 8);
        } else if (!(e->cflags & CF_COINBASE)) {
            e->major = (uint32_t)rd_varint(r);
            e->minor = (uint32_t)rd_varint(r);
        }
        e->amount = rd_varint(r);
        e->anchor = rd_bytes(r, 16);
        if (e->cflags & CF_SELFSEND) e->ss_De = rd_bytes(r, 32);
    } else {
        return false;
    }
    return r->ok;
}

static void commitment_mask(uint8_t mask[32], const uint8_t s[32])
{
    // rct::genCommitmentMask: H_s("commitment_mask" || s)
    uint8_t buf[15 + 32];
    memcpy(buf, "commitment_mask", 15);
    memcpy(buf + 15, s, 32);
    cw_hash_to_scalar(buf, sizeof(buf), mask);
    cw_wipe(buf, sizeof(buf));
}

// import_cold_output + make_sal_opening_hint_from_transfer_details + scan
static bool etd_to_input(const cw_keys_t *k, const etd_t *e, cw_input_t *in, char *err, size_t err_len)
{
    memset(in, 0, sizeof(*in));
    in->amount = e->amount;
    if (e->ver == 1) {
        in->j.major = e->major;
        in->j.minor = e->minor;
        in->biased = 1;
        in->spent = (e->pflags & PF_SPENT) ? 1 : 0;
        in->global_index = e->global_idx;
        memcpy(in->O, e->pubkey, 32);

        uint8_t spend_pub[32];
        cw_addr_spend_pub(k, in->j, spend_pub);
        const uint8_t *cand[2] = { e->tx_pubkey, NULL };
        if (e->internal_idx < e->n_additional) {
            const uint8_t *add = e->additional + 32 * e->internal_idx;
            if (!cw_subaddr_is_main(in->j)) { cand[0] = add; cand[1] = e->tx_pubkey; }
            else cand[1] = add;
        }
        for (int c = 0; c < 2 && cand[c]; c++) {
            uint8_t D[32], s[32], sG[32], O[32];
            if (!cw_key_derivation(D, cand[c], k->k_v)) continue;
            cw_derivation_to_scalar(s, D, e->internal_idx);
            cw_pt_base(sG, s);
            if (!cw_pt_add(O, spend_pub, sG) || !cw_pt_eq(O, e->pubkey)) continue;
            memcpy(in->ext_g, s, 32);
            if (e->pflags & PF_RCT) commitment_mask(in->mask, s);
            else { memset(in->mask, 0, 32); in->mask[0] = 1; }
            cw_commit(in->C, in->amount, in->mask);
            cw_wipe(D, 32); cw_wipe(s, 32);
            return true;
        }
        if (err) snprintf(err, err_len, "pre-Carrot output does not belong to this wallet");
        return false;
    }

    // Carrot
    if (e->cflags & CF_INTERNAL) { if (err) snprintf(err, err_len, "internal Carrot enotes are not supported"); return false; }
    if (e->cflags & CF_CARROT_ADDR) { if (err) snprintf(err, err_len, "Carrot-hierarchy addresses are not supported"); return false; }
    in->biased = 0;
    in->spent = (e->cflags & CF_SPENT) ? 1 : 0;
    if (!(e->cflags & (CF_HAS_PID | CF_COINBASE))) { in->j.major = e->major; in->j.minor = e->minor; }

    cw_enote_t en;
    uint8_t ic[33], s_ctx[32];
    if (e->cflags & CF_COINBASE) {
        if (!cw_make_coinbase_enote(&en, in->ext_g, in->ext_t, k, e->amount, e->anchor, e->block_index)) {
            if (err) snprintf(err, err_len, "cannot rebuild coinbase enote");
            return false;
        }
    } else {
        uint8_t spend_pub[32];
        cw_addr_spend_pub(k, in->j, spend_pub);
        if (e->cflags & CF_SELFSEND) {
            int type = (e->cflags & CF_CHANGE) ? CW_ENOTE_CHANGE : CW_ENOTE_PAYMENT;
            if (!cw_make_special_enote(&en, k, spend_pub, e->amount, type, e->ss_De, e->first_ki)) {
                if (err) snprintf(err, err_len, "cannot rebuild self-send enote");
                return false;
            }
        } else {
            cw_dest_t d;
            memset(&d, 0, sizeof(d));
            memcpy(d.spend_pub, spend_pub, 32);
            cw_addr_view_pub(k, in->j, d.view_pub);
            d.is_subaddress = !cw_subaddr_is_main(in->j);
            if (e->cflags & CF_HAS_PID) {
                static const uint8_t zero[8] = { 0 };
                if (memcmp(e->pid, zero, 8) != 0) { d.has_pid = 1; memcpy(d.pid, e->pid, 8); }
            }
            uint8_t pid_enc[8];
            if (!cw_make_normal_enote(&en, pid_enc, &d, e->amount, e->anchor, e->first_ki)) {
                if (err) snprintf(err, err_len, "cannot rebuild normal enote");
                return false;
            }
        }
        cw_input_context_rct(ic, e->first_ki);
        cw_receiver_s_ctx(s_ctx, k, en.D_e, ic);
        cw_sender_extensions(in->ext_g, in->ext_t, s_ctx, en.C_a);
        cw_wipe(s_ctx, 32);
    }
    memcpy(in->O, en.Ko, 32);
    memcpy(in->C, en.C_a, 32);
    memcpy(in->mask, en.k_a, 32);
    return true;
}

// ===========================================================================
// предложение транзакции (HotColdCarrotTransactionProposalV1)
// ===========================================================================
typedef struct {
    const uint8_t *raw;  size_t raw_len;
    const uint8_t *seed;
    size_t n_in;   const uint8_t *in_otas;
    size_t n_norm; cw_dest_t norm[MAX_OUTPUTS]; uint64_t norm_amount[MAX_OUTPUTS];
    size_t n_ss;   cw_subaddr_t ss_j[MAX_OUTPUTS]; uint64_t ss_amount[MAX_OUTPUTS]; uint8_t ss_type[MAX_OUTPUTS];
    uint64_t derive_type, fee;
    const uint8_t *extra; size_t extra_len;
} proposal_t;

static bool parse_proposal(rd_t *r, proposal_t *p)
{
    memset(p, 0, sizeof(*p));
    size_t start = r->pos;
    p->seed = rd_bytes(r, 32);
    p->n_in = (size_t)rd_varint(r);
    if (!r->ok || p->n_in == 0 || p->n_in > MAX_INPUTS) return false;
    p->in_otas = rd_bytes(r, 32 * p->n_in);
    p->n_norm = (size_t)rd_varint(r);
    if (!r->ok || p->n_norm > MAX_OUTPUTS) return false;
    for (size_t i = 0; i < p->n_norm; i++) {
        uint8_t flags = rd_u8(r);
        const uint8_t *s = rd_bytes(r, 32), *v = rd_bytes(r, 32);
        if (!r->ok) return false;
        cw_dest_t *d = &p->norm[i];
        memcpy(d->spend_pub, s, 32);
        memcpy(d->view_pub, v, 32);
        d->is_subaddress = flags & 1;
        if (flags & 2) {
            const uint8_t *pid = rd_bytes(r, 8);
            if (!pid) return false;
            static const uint8_t zero[8] = { 0 };
            if (memcmp(pid, zero, 8) != 0) { d->has_pid = 1; memcpy(d->pid, pid, 8); }
        }
        p->norm_amount[i] = rd_varint(r);
    }
    p->n_ss = (size_t)rd_varint(r);
    if (!r->ok || p->n_ss > MAX_OUTPUTS || p->n_norm + p->n_ss > MAX_OUTPUTS) return false;
    for (size_t i = 0; i < p->n_ss; i++) {
        p->ss_j[i].major = (uint32_t)rd_varint(r);
        p->ss_j[i].minor = (uint32_t)rd_varint(r);
        p->ss_amount[i] = rd_varint(r);
        uint64_t t = rd_varint(r);
        if (t > 1) return false;
        p->ss_type[i] = (uint8_t)t;
    }
    p->derive_type = rd_varint(r);
    p->fee = rd_varint(r);
    p->extra_len = (size_t)rd_varint(r);
    if (!r->ok || p->extra_len > MAX_EXTRA) return false;
    p->extra = rd_bytes(r, p->extra_len);
    p->raw = r->p + start;
    p->raw_len = r->pos - start;
    return r->ok;
}

// ===========================================================================
// набор входов: из файла и из хранилища
// ===========================================================================
typedef struct {
    cw_input_t *v;
    size_t n;
} inset_t;

// collect_non_burned_transfers_by_onetime_address: без потраченных, бо́льшая сумма
static const cw_input_t *inset_find(const inset_t *s, const uint8_t O[32])
{
    const cw_input_t *best = NULL;
    for (size_t i = 0; i < s->n; i++) {
        const cw_input_t *c = &s->v[i];
        if (memcmp(c->O, O, 32) != 0) continue;
        if (c->spent) return NULL;
        if (!best || c->amount > best->amount ||
            (c->amount == best->amount && c->global_index < best->global_index))
            best = c;
    }
    return best;
}

static bool lookup_input(const inset_t *s, const uint8_t O[32], cw_input_t *out)
{
    const cw_input_t *c = inset_find(s, O);
    if (c) { *out = *c; return true; }
    return cw_store_find(O, out);
}

// ===========================================================================
// разворот предложения
// ===========================================================================
typedef struct {
    size_t n_in, n_out;
    cw_input_t in[MAX_INPUTS];          // в порядке предложения
    uint8_t    ki[MAX_INPUTS][32];      // в порядке предложения
    size_t     order[MAX_INPUTS];       // отсортированный по KI (убывание) -> индекс предложения
    cw_rerand_t rr[MAX_INPUTS];         // в порядке предложения
    cw_enote_t out[MAX_OUTPUTS];        // отсортированы по Ko
    uint8_t    pid_enc[8];
    uint8_t    signable_hash[32];
} expanded_t;

static void derive_hc_anchor(uint8_t anchor[16], const uint8_t seed[32], uint8_t idx)
{
    cw_tr_t t;
    cw_tr_init(&t, DS_HC_NORMAL_ANCHOR);
    cw_tr_u8(&t, idx);
    cw_blake2b_carrot(seed, t.buf, t.n, anchor, 16);
}

static void derive_hc_special(uint8_t d_e[32], const uint8_t seed[32], uint8_t idx)
{
    cw_tr_t t;
    cw_tr_init(&t, DS_HC_SPECIAL_EPHEM);
    cw_tr_u8(&t, idx);
    cw_derive_scalar(seed, t.buf, t.n, d_e);
}

static void derive_hc_rerand(uint8_t r[32], const uint8_t seed[32], uint32_t input_idx, char type)
{
    cw_tr_t t;
    cw_tr_init(&t, DS_HC_RERAND);
    cw_tr_u32(&t, input_idx);
    cw_tr_u8(&t, (uint8_t)type);
    cw_derive_scalar(seed, t.buf, t.n, r);
}

// tx_extra: разобрать и собрать в порядке sort_tx_extra
typedef struct { uint8_t tag; const uint8_t *p; size_t len; } xfield_t;

static bool extra_parse(const uint8_t *x, size_t n, xfield_t *f, size_t *nf, size_t maxf)
{
    rd_t r = { x, n, 0, true };
    *nf = 0;
    while (r.pos < r.n) {
        if (*nf >= maxf) return false;
        size_t start = r.pos;
        uint8_t tag = rd_u8(&r);
        if (tag == 0x00) {
            size_t cnt = 1;
            while (r.pos < r.n) { if (rd_u8(&r) != 0) return false; cnt++; }
            if (cnt > 255) return false;
        } else if (tag == 0x01) {
            rd_bytes(&r, 32);
        } else if (tag == 0x02 || tag == 0x03 || tag == 0xDE) {
            size_t l = (size_t)rd_varint(&r);
            if (tag == 0x02 && l > 255) return false;
            rd_bytes(&r, l);
        } else if (tag == 0x04) {
            size_t k = (size_t)rd_varint(&r);
            if (k > 4096) return false;
            rd_bytes(&r, 32 * k);
        } else {
            return false;
        }
        if (!r.ok) return false;
        f[*nf].tag = tag;
        f[*nf].p = x + start;
        f[*nf].len = r.pos - start;
        (*nf)++;
    }
    return true;
}

static bool build_extra(wr_t *out, const expanded_t *E, const proposal_t *p)
{
    uint8_t carrot[2 + 10 + 32 * MAX_OUTPUTS + 12];
    size_t cn = 0;
    bool shared = E->n_out == 1 || (E->n_out == 2 && memcmp(E->out[0].D_e, E->out[1].D_e, 32) == 0);
    if (shared) {
        carrot[cn++] = 0x01;
        memcpy(carrot + cn, E->out[0].D_e, 32);
        cn += 32;
    } else {
        carrot[cn++] = 0x04;
        carrot[cn++] = (uint8_t)E->n_out;              // < 0x80
        for (size_t i = 0; i < E->n_out; i++) { memcpy(carrot + cn, E->out[i].D_e, 32); cn += 32; }
    }
    carrot[cn++] = 0x02;          // nonce
    carrot[cn++] = 9;
    carrot[cn++] = 0x01;          // TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID
    memcpy(carrot + cn, E->pid_enc, 8);
    cn += 8;

    xfield_t f[64];
    size_t nf1 = 0, nf2 = 0;
    if (!extra_parse(carrot, cn, f, &nf1, 64)) return false;
    if (p->extra_len && !extra_parse(p->extra, p->extra_len, f + nf1, &nf2, 64 - nf1)) return false;
    size_t nf = nf1 + nf2;
    static const uint8_t order[] = { 0x01, 0x04, 0x02, 0x03, 0xDE, 0x00 };
    for (size_t o = 0; o < sizeof(order); o++)
        for (size_t i = 0; i < nf; i++)
            if (f[i].tag == order[o]) wr_put(out, f[i].p, f[i].len);
    return out->ok;
}


static bool expand_proposal(const cw_wallet_t *w, const proposal_t *p, const inset_t *inset,
                            expanded_t *E, char *err, size_t err_len)
{
    const cw_keys_t *k = &w->keys;
    memset(E, 0, sizeof(*E));
    E->n_in = p->n_in;
    E->n_out = p->n_norm + p->n_ss;

    if (p->derive_type != 0 && p->derive_type != 1)
        ERR("unsupported address derive type %u", (unsigned)p->derive_type);
    if (p->n_ss == 0) ERR("transaction has no self-send output");
    if (E->n_out < 2) ERR("too few outputs");

    // 1. входы и key images
    for (size_t i = 0; i < E->n_in; i++) {
        const uint8_t *O = p->in_otas + 32 * i;
        if (!lookup_input(inset, O, &E->in[i]))
            ERR("input %u is unknown to the device: send the outputs file first", (unsigned)i);
        cw_input_key_image(E->ki[i], k, &E->in[i]);
    }
    for (size_t i = 0; i < E->n_in; i++) E->order[i] = i;
    for (size_t a = 1; a < E->n_in; a++) {          // убывание по memcmp, затем по индексу
        size_t v = E->order[a], b = a;
        while (b > 0) {
            int c = memcmp(E->ki[E->order[b - 1]], E->ki[v], 32);
            if (c > 0 || (c == 0 && E->order[b - 1] > v)) break;
            E->order[b] = E->order[b - 1];
            b--;
        }
        E->order[b] = v;
    }
    for (size_t a = 1; a < E->n_in; a++)
        if (memcmp(E->ki[E->order[a - 1]], E->ki[E->order[a]], 32) == 0) ERR("duplicate key image");
    const uint8_t *first_ki = E->ki[E->order[0]];
    uint8_t ic[33];
    cw_input_context_rct(ic, first_ki);

    // 2. выходы
    uint8_t anchors[MAX_OUTPUTS][16];
    uint8_t ss_de[MAX_OUTPUTS][32];
    bool ss_has_de[MAX_OUTPUTS];
    for (size_t i = 0; i < p->n_norm; i++) derive_hc_anchor(anchors[i], p->seed, (uint8_t)i);
    for (size_t i = 0; i < p->n_ss; i++) { derive_hc_special(ss_de[i], p->seed, (uint8_t)i); ss_has_de[i] = true; }
    if (E->n_out == 2) ss_has_de[p->n_ss - 1] = false;
    {
        cw_tr_t t;
        cw_tr_init(&t, DS_HC_DUMMY_PID);
        cw_blake2b_carrot(p->seed, t.buf, t.n, E->pid_enc, 8);
    }
    for (size_t i = 0; i < p->n_norm; i++)
        for (size_t j = 0; j < i; j++)
            if (memcmp(anchors[i], anchors[j], 16) == 0) ERR("duplicate anchor");

    size_t no = 0, n_integrated = 0;
    for (size_t i = 0; i < p->n_norm; i++) {
        uint8_t pid_enc[8];
        if (!cw_make_normal_enote(&E->out[no], pid_enc, &p->norm[i], p->norm_amount[i], anchors[i], first_ki))
            ERR("invalid destination address in output %u", (unsigned)i);
        if (p->norm[i].has_pid) { memcpy(E->pid_enc, pid_enc, 8); n_integrated++; }
        no++;
    }
    if (n_integrated > 1) ERR("more than one integrated address");

    bool is_2out_normal = E->n_out == 2 && p->n_norm == 1;
    bool is_2out_ss = E->n_out == 2 && p->n_ss == 2;
    for (size_t i = 0; i < p->n_ss; i++) {
        uint8_t D_e[32], spend_pub[32];
        if (is_2out_normal) {
            uint8_t d_e[32];
            if (ss_has_de[i]) ERR("self-send in a 2-out tx has its own ephemeral key");
            if (!cw_normal_ephemeral(d_e, D_e, &p->norm[0], anchors[0], ic)) ERR("bad normal D_e");
            cw_wipe(d_e, 32);
        } else {
            size_t base = i;
            const uint8_t *d_e = ss_has_de[i] ? ss_de[i] : NULL;
            if (is_2out_ss) {
                size_t other = 1 - i;
                if (p->ss_type[other] == p->ss_type[i]) ERR("2-out self-sends must have different types");
                base = (p->ss_type[other] == CW_ENOTE_PAYMENT) ? other : i;
                if (ss_has_de[other]) {
                    if (d_e && memcmp(d_e, ss_de[other], 32) != 0) ERR("conflicting ephemeral keys");
                    d_e = ss_de[other];
                }
            }
            if (!d_e) ERR("no ephemeral key for self-send");
            uint8_t base_pub[32];
            cw_addr_spend_pub(k, p->ss_j[base], base_pub);
            if (!cw_ephemeral_pub(D_e, d_e, base_pub, !cw_subaddr_is_main(p->ss_j[base]))) ERR("bad self-send D_e");
        }
        cw_addr_spend_pub(k, p->ss_j[i], spend_pub);
        if (!cw_make_special_enote(&E->out[no], k, spend_pub, p->ss_amount[i], p->ss_type[i], D_e, first_ki))
            ERR("cannot build self-send output");
        no++;
    }
    // сортировка по Ko
    for (size_t a = 1; a < no; a++) {
        cw_enote_t v = E->out[a];
        size_t b = a;
        while (b > 0 && memcmp(E->out[b - 1].Ko, v.Ko, 32) > 0) { E->out[b] = E->out[b - 1]; b--; }
        E->out[b] = v;
    }
    for (size_t a = 0; a < no; a++) {
        if (a && memcmp(E->out[a - 1].Ko, E->out[a].Ko, 32) == 0) ERR("duplicate one-time address");
        if (!cw_pt_in_main_subgroup(E->out[a].Ko)) ERR("invalid one-time address");
        if (cw_sc_is_zero(E->out[a].k_a)) ERR("trivial blinding factor");
        for (size_t b = 0; b < a; b++) {
            if (memcmp(E->out[a].k_a, E->out[b].k_a, 32) == 0) ERR("duplicate blinding factor");
            bool same_de = memcmp(E->out[a].D_e, E->out[b].D_e, 32) == 0;
            if (E->n_out != 2 && same_de) ERR("duplicate ephemeral pubkeys");
        }
    }
    if (E->n_out == 2 && memcmp(E->out[0].D_e, E->out[1].D_e, 32) != 0) ERR("2-out set must share D_e");

    // баланс
    {
        uint64_t sum_in = 0, sum_out = p->fee;
        for (size_t i = 0; i < E->n_in; i++) {
            if (sum_in + E->in[i].amount < sum_in) ERR("input amount overflow");
            sum_in += E->in[i].amount;
        }
        for (size_t i = 0; i < no; i++) {
            if (sum_out + E->out[i].amount < sum_out) ERR("output amount overflow");
            sum_out += E->out[i].amount;
        }
        if (sum_in != sum_out) ERR("inputs do not balance outputs + fee");
    }

    // 3. рерандомизация (порядок предложения), последний r_c балансирует
    {
        uint8_t r_c[32] = { 0 };
        for (size_t i = 0; i < no; i++) cw_sc_add(r_c, r_c, E->out[i].k_a);
        for (size_t i = 0; i < E->n_in; i++) cw_sc_sub(r_c, r_c, E->in[i].mask);
        for (size_t i = 0; i < E->n_in; i++) {
            uint8_t r_o[32], r_i[32], r_r_i[32], rc[32];
            derive_hc_rerand(r_o, p->seed, (uint32_t)i, 'o');
            derive_hc_rerand(r_i, p->seed, (uint32_t)i, 'i');
            derive_hc_rerand(r_r_i, p->seed, (uint32_t)i, 'r');
            derive_hc_rerand(rc, p->seed, (uint32_t)i, 'c');
            if (i + 1 < E->n_in) cw_sc_sub(r_c, r_c, rc);
            else memcpy(rc, r_c, 32);
            if (!cw_rerandomize(&E->rr[i], E->in[i].O, E->in[i].C, E->in[i].biased, r_o, r_i, r_r_i, rc))
                ERR("rerandomization failed");
        }
    }

    // 4. signable tx hash = H(prefix_hash || H(rctSigBase))
    {
        wr_t t = { 0 };
        t.ok = true;
        wr_varint(&t, 2);                       // version
        wr_varint(&t, 0);                       // unlock_time
        wr_varint(&t, E->n_in);
        for (size_t a = 0; a < E->n_in; a++) {
            wr_u8(&t, 0x02);                    // txin_to_key
            wr_varint(&t, 0);                   // amount
            wr_varint(&t, 0);                   // key_offsets
            wr_put(&t, E->ki[E->order[a]], 32);
        }
        wr_varint(&t, no);
        for (size_t i = 0; i < no; i++) {
            wr_varint(&t, 0);
            wr_u8(&t, 0x01);                    // txout_to_carrot_v1
            wr_put(&t, E->out[i].Ko, 32);
            wr_put(&t, E->out[i].view_tag, 3);
            wr_put(&t, E->out[i].anchor_enc, 16);
        }
        wr_t x = { 0 };
        x.ok = true;
        if (!build_extra(&x, E, p)) { wr_free(&t); wr_free(&x); ERR("bad tx_extra"); }
        wr_varint(&t, x.n);
        wr_put(&t, x.p, x.n);
        wr_free(&x);
        if (!t.ok) { wr_free(&t); ERR("out of memory"); }
        uint8_t hh[64];
        cw_keccak(t.p, t.n, hh);                // prefix hash
        wr_free(&t);

        t.ok = true;
        wr_u8(&t, 7);                           // RCTTypeFcmpPlusPlus
        wr_varint(&t, p->fee);
        for (size_t i = 0; i < no; i++) wr_put(&t, E->out[i].a_enc, 8);
        for (size_t i = 0; i < no; i++) wr_put(&t, E->out[i].C_a, 32);
        if (!t.ok) { wr_free(&t); ERR("out of memory"); }
        cw_keccak(t.p, t.n, hh + 32);
        wr_free(&t);
        cw_keccak(hh, 64, E->signable_hash);
    }
    return true;
fail:
    return false;
}

// ===========================================================================
// доказательство связи key image с выходом (prove_key_image_proof)
// ===========================================================================
// proof: tag + данные; возвращает длину
static size_t ki_proof(const cw_keys_t *k, const cw_input_t *in, uint8_t L[32], uint8_t *proof)
{
    uint8_t x[32];
    cw_input_x(x, k, in);
    size_t n = 0;
    if (cw_sc_is_zero(in->ext_t)) {
        // одночленная кольцевая подпись, Hp — старый
        uint8_t I[32], O[32];
        cw_pt_base(O, x);
        cw_hp_biased(I, O);
        cw_pt_mul(L, x, I);
        proof[0] = TAG_SIGNATURE;
        cw_ring1_signature(proof + 1, L, L, O, x);
        n = 1 + 64;
    } else {
        cw_rerand_t rr;
        memset(&rr, 0, sizeof(rr));
        memcpy(rr.O_tilde, in->O, 32);
        cw_ki_generator(rr.I_tilde, in->O, in->biased);
        memcpy(rr.R, CW_IDENTITY, 32);
        memcpy(rr.C_tilde, CW_IDENTITY, 32);
        cw_pt_mul(L, x, rr.I_tilde);
        uint8_t prefix[32];
        cw_tr_t t;
        cw_tr_init(&t, DS_KI_PROOF);
        cw_tr_add(&t, in->O, 32);
        cw_tr_u8(&t, in->biased);
        cw_tr_add(&t, L, 32);
        cw_blake2b_carrot(NULL, t.buf, t.n, prefix, 32);
        proof[0] = TAG_SAL;
        proof[1] = (uint8_t)(0x80 | (CW_SAL_PROOF_SIZE & 0x7f));   // varint 384
        proof[2] = (uint8_t)(CW_SAL_PROOF_SIZE >> 7);
        uint8_t L2[32];
        if (!cw_sal_prove(proof + 3, L2, prefix, &rr, x, in->ext_t) || !cw_pt_eq(L, L2)) n = 0;
        else n = 3 + CW_SAL_PROOF_SIZE;
    }
    cw_wipe(x, 32);
    return n;
}


static bool ki_proof_verify(const cw_keys_t *k, const cw_input_t *in, const uint8_t L[32],
                            const uint8_t *proof, size_t len)
{
    uint8_t Lme[32], mine[3 + CW_SAL_PROOF_SIZE];
    size_t ml = ki_proof(k, in, Lme, mine);       // заодно считает наш L
    if (!ml || !cw_pt_eq(L, Lme) || len < 1 || proof[0] != mine[0]) return false;
    if (proof[0] == TAG_SIGNATURE) {
        uint8_t O[32], x[32];
        cw_input_x(x, k, in);
        cw_pt_base(O, x);
        cw_wipe(x, 32);
        return len == 65 && cw_ring1_check(proof + 1, L, L, O);
    }
    if (len != 3 + CW_SAL_PROOF_SIZE) return false;
    uint8_t I[32], prefix[32];
    cw_ki_generator(I, in->O, in->biased);
    cw_tr_t t;
    cw_tr_init(&t, DS_KI_PROOF);
    cw_tr_add(&t, in->O, 32);
    cw_tr_u8(&t, in->biased);
    cw_tr_add(&t, L, 32);
    cw_blake2b_carrot(NULL, t.buf, t.n, prefix, 32);
    return cw_sal_verify(proof + 3, prefix, in->O, I, CW_IDENTITY, CW_IDENTITY, L);
}

// ===========================================================================
// unsigned tx set v6 -> signed tx set v6
// ===========================================================================
typedef struct {
    uint8_t ki[32];
    uint8_t ota[32];
    uint8_t proof[CW_SAL_PROOF_SIZE];
} signed_input_t;

static int cmp_signed_desc(const void *a, const void *b) { return -memcmp(a, b, 32); }

typedef struct {
    proposal_t *props; size_t n_props;
    inset_t inset;
    uint64_t starting_index;
    size_t   n_new_total;     // выходов в файле (включая пропущенные)
    bool resend;
    const uint8_t *props_raw; size_t props_raw_len;   // вектор tx_proposals как в файле
} unsigned_set_t;

static bool parse_unsigned_set(const cw_wallet_t *w, const uint8_t *pt, size_t pt_len,
                               unsigned_set_t *u, char *err, size_t err_len)
{
    memset(u, 0, sizeof(*u));
    rd_t r = { pt, pt_len, 0, true };
    uint64_t ver = rd_varint(&r);
    if (!r.ok) ERR("unsigned tx set is truncated");
    if (ver != 3) ERR("pre-Carrot unsigned tx set (variant %u) is not supported", (unsigned)ver);
    size_t props_start = r.pos;
    u->n_props = (size_t)rd_varint(&r);
    if (!r.ok || u->n_props == 0 || u->n_props > 16) ERR("bad number of transactions");
    u->props = (proposal_t *)cw_malloc(sizeof(proposal_t) * u->n_props);
    if (!u->props) ERR("out of memory");
    for (size_t i = 0; i < u->n_props; i++)
        if (!parse_proposal(&r, &u->props[i])) ERR("cannot parse transaction %u", (unsigned)i);
    u->props_raw = pt + props_start;
    u->props_raw_len = r.pos - props_start;

    size_t n_new = (size_t)rd_varint(&r);
    if (!r.ok || n_new > 100000) ERR("bad number of outputs");
    if (n_new) {
        u->inset.v = (cw_input_t *)cw_malloc(sizeof(cw_input_t) * n_new);
        if (!u->inset.v) ERR("out of memory");
    }
    for (size_t i = 0; i < n_new; i++) {
        etd_t e;
        if (!parse_etd(&r, &e)) ERR("cannot parse output %u", (unsigned)i);
        if (!etd_to_input(&w->keys, &e, &u->inset.v[u->inset.n], err, err_len)) {
            cw_log("output %u skipped: %s", (unsigned)i, err ? err : "");
            continue;
        }
        cw_store_put(&u->inset.v[u->inset.n]);
        u->inset.n++;
    }
    u->n_new_total = n_new;
    u->starting_index = rd_varint(&r);
    u->resend = rd_u8(&r) != 0;
    if (!r.ok) ERR("unsigned tx set is truncated");
    if (r.pos != r.n) ERR("trailing data in unsigned tx set");
    return true;
fail:
    return false;
}

static void free_unsigned_set(unsigned_set_t *u)
{
    if (u->props) cw_free(u->props);
    if (u->inset.v) { cw_wipe(u->inset.v, sizeof(cw_input_t) * u->inset.n); cw_free(u->inset.v); }
    memset(u, 0, sizeof(*u));
}

static void log_tx(const cw_wallet_t *w, const proposal_t *p, size_t idx)
{
    (void)w;
    cw_log("tx %u: %u inputs, %u payments, %u self-sends, fee %llu",
           (unsigned)idx, (unsigned)p->n_in, (unsigned)p->n_norm, (unsigned)p->n_ss,
           (unsigned long long)p->fee);
    for (size_t i = 0; i < p->n_norm; i++) {
        char hex[17];
        for (int b = 0; b < 8; b++) snprintf(hex + 2 * b, 3, "%02x", p->norm[i].spend_pub[b]);
        cw_log("  pay %llu.%012llu XMR to %s%s... ",
               (unsigned long long)(p->norm_amount[i] / 1000000000000ULL),
               (unsigned long long)(p->norm_amount[i] % 1000000000000ULL),
               p->norm[i].is_subaddress ? "subaddr " : "", hex);
    }
}

bool cw_sign_unsigned_set(const cw_wallet_t *w, const uint8_t *file, size_t len,
                          uint8_t **out, size_t *out_len, char *err, size_t err_len)
{
    return cw_sign_unsigned_set2(w, file, len, out, out_len, NULL, NULL, err, err_len);
}

bool cw_sign_unsigned_set2(const cw_wallet_t *w, const uint8_t *file, size_t len,
                           uint8_t **out, size_t *out_len, uint8_t **ki_out, size_t *ki_len,
                           char *err, size_t err_len)
{
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    int kind, version;
    unsigned_set_t u;
    memset(&u, 0, sizeof(u));
    expanded_t *E = NULL;
    signed_input_t *si = NULL;
    size_t n_si = 0, cap_si = 0;
    wr_t wout = { 0 };
    wout.ok = true;
    bool ok = false;

    if (!cw_decrypt_file(w, file, len, &pt, &pt_len, &kind, &version))
        ERR("cannot decrypt: file is not for this wallet or is damaged");
    if (kind != CW_FILE_UNSIGNED) ERR("not an unsigned tx set");
    if (version != 6) ERR("unsigned tx set version %d is not supported (need 6)", version);
    if (!parse_unsigned_set(w, pt, pt_len, &u, err, err_len)) goto fail;
    cw_progress("unsigned tx set: %u tx, %u outputs", (unsigned)u.n_props, (unsigned)u.inset.n);

    E = (expanded_t *)cw_malloc(sizeof(expanded_t));
    if (!E) ERR("out of memory");

    for (size_t t = 0; t < u.n_props; t++) {
        const proposal_t *p = &u.props[t];
        log_tx(w, p, t);
        if (!expand_proposal(w, p, &u.inset, E, err, err_len)) goto fail;
        if (n_si + E->n_in > cap_si) {
            size_t nc = (n_si + E->n_in) * 2;
            signed_input_t *ns = (signed_input_t *)cw_malloc(sizeof(signed_input_t) * nc);
            if (!ns) ERR("out of memory");
            if (si) { memcpy(ns, si, sizeof(signed_input_t) * n_si); cw_free(si); }
            si = ns;
            cap_si = nc;
        }
        for (size_t a = 0; a < E->n_in; a++) {
            size_t i = E->order[a];
            cw_progress("tx %u: SA/L %u/%u", (unsigned)t, (unsigned)(a + 1), (unsigned)E->n_in);
            uint8_t x[32], L[32];
            cw_input_x(x, &w->keys, &E->in[i]);
            bool r = cw_sal_prove(si[n_si].proof, L, E->signable_hash, &E->rr[i], x, E->in[i].ext_t);
            cw_wipe(x, 32);
            if (!r) ERR("SA/L proof failed for input %u", (unsigned)i);
            if (!cw_pt_eq(L, E->ki[i])) ERR("key image mismatch for input %u", (unsigned)i);
            memcpy(si[n_si].ki, L, 32);
            memcpy(si[n_si].ota, E->in[i].O, 32);
            n_si++;
        }
    }
    qsort(si, n_si, sizeof(signed_input_t), cmp_signed_desc);
    for (size_t a = 1; a < n_si; a++)
        if (memcmp(si[a - 1].ki, si[a].ki, 32) == 0) ERR("the same input is spent twice");

    // SignedCarrotTransactionSetV1
    wr_varint(&wout, 1);
    if (u.resend) wr_put(&wout, u.props_raw, u.props_raw_len);
    else wr_varint(&wout, 0);
    wr_varint(&wout, n_si);
    for (size_t a = 0; a < n_si; a++) {
        wr_u8(&wout, 2);
        wr_put(&wout, si[a].ki, 32);
        wr_u8(&wout, 2);
        wr_put(&wout, si[a].ota, 32);
        wr_varint(&wout, CW_SAL_PROOF_SIZE);
        wr_put(&wout, si[a].proof, CW_SAL_PROOF_SIZE);
    }
    // other_key_images: лучшие непотраченные выходы набора, которых нет среди входов
    {
        size_t n_other = 0;
        uint8_t *mark = NULL;
        if (u.inset.n) {
            mark = (uint8_t *)cw_malloc(u.inset.n);
            if (!mark) ERR("out of memory");
            memset(mark, 0, u.inset.n);
        }
        for (size_t i = 0; i < u.inset.n; i++) {
            const cw_input_t *best = inset_find(&u.inset, u.inset.v[i].O);
            if (best != &u.inset.v[i]) continue;
            bool used = false;
            for (size_t a = 0; a < n_si && !used; a++) used = memcmp(si[a].ota, best->O, 32) == 0;
            if (used) continue;
            mark[i] = 1;
            n_other++;
        }
        wr_varint(&wout, n_other);
        uint8_t proof[3 + CW_SAL_PROOF_SIZE];
        for (size_t i = 0; i < u.inset.n; i++) {
            if (!mark[i]) continue;
            uint8_t L[32];
            size_t pl = ki_proof(&w->keys, &u.inset.v[i], L, proof);
            if (!pl) { cw_free(mark); ERR("key image proof failed"); }
            wr_u8(&wout, 2);
            wr_put(&wout, u.inset.v[i].O, 32);
            wr_u8(&wout, 2);
            wr_put(&wout, L, 32);
            wr_put(&wout, proof, pl);
        }
        if (mark) cw_free(mark);
    }
    if (!wout.ok) ERR("out of memory");
    if (!encrypt_file(w, CW_FILE_SIGNED, 6, wout.p, wout.n, out, out_len)) ERR("out of memory");
    if (ki_out) {
        // Спутник "<signed>_keyImages": monero-wallet-gui после подписи делает
        // export_key_images(all=false). Холодный кошелёк к этому моменту знает
        // все выходы горячего, ни один не запрошен: пустой список, offset =
        // число выходов горячего кошелька (key_image_message_v3).
        uint64_t off = u.starting_index + u.n_new_total;
        uint8_t msg[4 + 64];
        for (int b = 0; b < 4; b++) msg[b] = (uint8_t)(off >> (8 * b));
        memcpy(msg + 4, w->keys.K_s, 32);
        memcpy(msg + 36, w->keys.K_v, 32);
        if (!encrypt_file(w, CW_FILE_KEYIMAGES, 3, msg, sizeof(msg), ki_out, ki_len)) {
            cw_free(*out);
            *out = NULL;
            ERR("out of memory");
        }
    }
    ok = true;

fail:
    wr_free(&wout);
    if (E) { cw_wipe(E, sizeof(*E)); cw_free(E); }
    if (si) cw_free(si);
    free_unsigned_set(&u);
    if (pt) { cw_wipe(pt, pt_len); cw_free(pt); }
    return ok;
}

// ===========================================================================
// outputs v5 (или v4) -> key images v4 (или v3)
// ===========================================================================
bool cw_export_key_images(const cw_wallet_t *w, const uint8_t *file, size_t len,
                          uint8_t **out, size_t *out_len, char *err, size_t err_len)
{
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    int kind, version;
    cw_input_t *ins = NULL;
    uint8_t (*kis)[32] = NULL;
    uint8_t *proofs = NULL;
    size_t *plen = NULL;
    wr_t wout = { 0 };
    wout.ok = true;
    bool ok = false;

    if (!cw_decrypt_file(w, file, len, &pt, &pt_len, &kind, &version))
        ERR("cannot decrypt: file is not for this wallet or is damaged");
    if (kind != CW_FILE_OUTPUTS) ERR("not an outputs file");
    if (version != 4 && version != 5) ERR("outputs file version %d is not supported", version);

    rd_t r = { pt, pt_len, 0, true };
    const uint8_t *Ks = rd_bytes(&r, 32), *Kv = rd_bytes(&r, 32);
    if (!r.ok || !cw_pt_eq(Ks, w->keys.K_s) || !cw_pt_eq(Kv, w->keys.K_v))
        ERR("outputs file is meant for another wallet");
    uint64_t offset, total;
    size_t n;
    if (version == 5) {
        offset = rd_varint(&r);
        total = rd_varint(&r);
        n = (size_t)rd_varint(&r);
    } else {
        // tuple<u64,u64,vector>: varint(3) || offset || size || vector
        if (rd_varint(&r) != 3) ERR("bad outputs file");
        offset = rd_varint(&r);
        total = rd_varint(&r);
        n = (size_t)rd_varint(&r);
    }
    (void)total;
    if (!r.ok || n > 100000) ERR("bad outputs file");
    ins = (cw_input_t *)cw_malloc(sizeof(cw_input_t) * (n ? n : 1));
    kis = (uint8_t (*)[32])cw_malloc(32 * (n ? n : 1));
    proofs = (uint8_t *)cw_malloc((3 + CW_SAL_PROOF_SIZE) * (n ? n : 1));
    plen = (size_t *)cw_malloc(sizeof(size_t) * (n ? n : 1));
    if (!ins || !kis || !proofs || !plen) ERR("out of memory");

    bool all_sig = true;
    for (size_t i = 0; i < n; i++) {
        etd_t e;
        if (version == 5) {
            if (!parse_etd(&r, &e)) ERR("cannot parse output %u", (unsigned)i);
        } else {
            // v4: exported_pre_carrot_transfer_details с версией внутри объекта
            if (!parse_etd(&r, &e) || e.ver != 1) ERR("cannot parse output %u", (unsigned)i);
        }
        {
            char why[96] = "";
            if (!etd_to_input(&w->keys, &e, &ins[i], why, sizeof(why))) ERR("output %u: %s", (unsigned)i, why);
        }
        cw_store_put(&ins[i]);
        cw_progress("key image %u/%u", (unsigned)(i + 1), (unsigned)n);
        plen[i] = ki_proof(&w->keys, &ins[i], kis[i], proofs + i * (3 + CW_SAL_PROOF_SIZE));
        if (!plen[i]) ERR("key image proof failed for output %u", (unsigned)i);
        if (proofs[i * (3 + CW_SAL_PROOF_SIZE)] != TAG_SIGNATURE) all_sig = false;
    }
    if (r.pos != r.n) ERR("trailing data in outputs file");

    if (all_sig) {
        // key_image_message_v3: offset(u32) || K_s || K_v || (KI || sig)*
        uint8_t o4[4] = { (uint8_t)offset, (uint8_t)(offset >> 8), (uint8_t)(offset >> 16), (uint8_t)(offset >> 24) };
        wr_put(&wout, o4, 4);
        wr_put(&wout, w->keys.K_s, 32);
        wr_put(&wout, w->keys.K_v, 32);
        for (size_t i = 0; i < n; i++) {
            wr_put(&wout, kis[i], 32);
            wr_put(&wout, proofs + i * (3 + CW_SAL_PROOF_SIZE) + 1, 64);
        }
    } else {
        wr_varint(&wout, offset);
        wr_put(&wout, w->keys.K_s, 32);
        wr_put(&wout, w->keys.K_v, 32);
        wr_varint(&wout, n);
        for (size_t i = 0; i < n; i++) {
            wr_u8(&wout, 2);
            wr_put(&wout, kis[i], 32);
            wr_put(&wout, proofs + i * (3 + CW_SAL_PROOF_SIZE), plen[i]);
        }
    }
    if (!wout.ok) ERR("out of memory");
    if (!encrypt_file(w, CW_FILE_KEYIMAGES, all_sig ? 3 : 4, wout.p, wout.n, out, out_len)) ERR("out of memory");
    ok = true;
fail:
    wr_free(&wout);
    if (ins) { cw_wipe(ins, sizeof(cw_input_t) * (n ? n : 1)); cw_free(ins); }
    if (kis) cw_free(kis);
    if (proofs) cw_free(proofs);
    if (plen) cw_free(plen);
    if (pt) { cw_wipe(pt, pt_len); cw_free(pt); }
    return ok;
}

// ===========================================================================
// проверка подписанного набора (для ПК)
// ===========================================================================
bool cw_verify_signed_set(const cw_wallet_t *w, const uint8_t *unsigned_file, size_t ulen,
                          const uint8_t *signed_file, size_t slen, char *err, size_t err_len)
{
    uint8_t *upt = NULL, *spt = NULL;
    size_t upt_len = 0, spt_len = 0;
    int kind, version;
    unsigned_set_t u;
    memset(&u, 0, sizeof(u));
    expanded_t *E = NULL;
    bool ok = false;

    if (!cw_decrypt_file(w, unsigned_file, ulen, &upt, &upt_len, &kind, &version) || kind != CW_FILE_UNSIGNED)
        ERR("cannot decrypt unsigned set");
    if (!cw_decrypt_file(w, signed_file, slen, &spt, &spt_len, &kind, &version) || kind != CW_FILE_SIGNED)
        ERR("cannot decrypt signed set");
    if (!parse_unsigned_set(w, upt, upt_len, &u, err, err_len)) goto fail;

    rd_t r = { spt, spt_len, 0, true };
    if (rd_varint(&r) != 1) ERR("signed set is not Carrot v1");
    size_t n_tx = (size_t)rd_varint(&r);
    for (size_t i = 0; i < n_tx; i++) {
        proposal_t p;
        if (!parse_proposal(&r, &p)) ERR("bad proposal in signed set");
    }
    size_t n_si = (size_t)rd_varint(&r);
    const uint8_t *si = r.p + r.pos;
    for (size_t a = 0; a < n_si; a++) {
        if (rd_u8(&r) != 2) ERR("bad pair");
        rd_bytes(&r, 32);
        if (rd_u8(&r) != 2) ERR("bad pair");
        rd_bytes(&r, 32);
        if (rd_varint(&r) != CW_SAL_PROOF_SIZE) ERR("bad SA/L size");
        rd_bytes(&r, CW_SAL_PROOF_SIZE);
    }
    {
        size_t n_oth = (size_t)rd_varint(&r);
        for (size_t a = 0; a < n_oth; a++) {
            if (rd_u8(&r) != 2) ERR("bad pair");
            const uint8_t *O = rd_bytes(&r, 32);
            if (rd_u8(&r) != 2) ERR("bad pair");
            const uint8_t *L = rd_bytes(&r, 32);
            size_t st = r.pos;
            uint8_t tag = rd_u8(&r);
            if (tag == TAG_SIGNATURE) rd_bytes(&r, 64);
            else { size_t l = (size_t)rd_varint(&r); rd_bytes(&r, l); }
            if (!r.ok) ERR("signed set truncated");
            const cw_input_t *in = inset_find(&u.inset, O);
            if (!in) ERR("other key image %u: unknown output", (unsigned)a);
            if (!ki_proof_verify(&w->keys, in, L, r.p + st, r.pos - st))
                ERR("other key image %u: proof does not verify", (unsigned)a);
        }
        if (r.pos != r.n) ERR("trailing data in signed set");
    }
    if (!r.ok) ERR("signed set truncated");
    const size_t rec = 1 + 32 + 1 + 32 + 2 + CW_SAL_PROOF_SIZE;

    E = (expanded_t *)cw_malloc(sizeof(expanded_t));
    size_t checked = 0;
    for (size_t t = 0; t < u.n_props; t++) {
        if (!expand_proposal(w, &u.props[t], &u.inset, E, err, err_len)) goto fail;
        for (size_t i = 0; i < E->n_in; i++) {
            const uint8_t *found = NULL;
            for (size_t a = 0; a < n_si; a++)
                if (memcmp(si + a * rec + 1, E->ki[i], 32) == 0) found = si + a * rec;
            if (!found) ERR("tx %u input %u: key image not in signed set", (unsigned)t, (unsigned)i);
            if (memcmp(found + 34, E->in[i].O, 32) != 0) ERR("one-time address mismatch");
            const uint8_t *proof = found + 68;
            if (!cw_sal_verify(proof, E->signable_hash, E->rr[i].O_tilde, E->rr[i].I_tilde,
                               E->rr[i].R, E->rr[i].C_tilde, E->ki[i]))
                ERR("tx %u input %u: SA/L does not verify against our expansion", (unsigned)t, (unsigned)i);
            checked++;
        }
    }
    if (checked != n_si) ERR("signed set has %u inputs, expected %u", (unsigned)n_si, (unsigned)checked);
    ok = true;
fail:
    if (E) cw_free(E);
    free_unsigned_set(&u);
    if (upt) cw_free(upt);
    if (spt) cw_free(spt);
    return ok;
}
