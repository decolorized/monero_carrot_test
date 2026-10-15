// rct_sig_construct.c
//
// Построение RCT-подписи Monero (RCTTypeBulletproofPlus).
// Сериализация rctSigBase, rctSigPrunable, вычисление full_message.

#include "rct_sig_construct.h"
#include "crypto-ops.h"
#include "hash-ops.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

extern void platform_log(const char *msg);
extern void platform_random_bytes(uint8_t *buf, size_t n);
extern void cn_fast_hash(const void *data, size_t length, char *hash);
extern uint8_t g_view_secret_key[32];

// ===========================================================================
// Диагностика
// ===========================================================================
static void logf_(const char *fmt, ...) {
    char buf[200];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    platform_log(buf);
}

static void log_hex32(const char *prefix, const uint8_t *p) {
    char buf[160];
    int n = snprintf(buf, sizeof(buf), "%s=", prefix);
    for (int i = 0; i < 32; i++) n += snprintf(buf + n, sizeof(buf) - n, "%02x", p[i]);
    platform_log(buf);
}

// ===========================================================================
// Утилиты
// ===========================================================================
static size_t put_varint(uint8_t *out, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)(v & 0x7f) | 0x80;
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

// H = toPoint(cn_fast_hash(G))
static const uint8_t H_BYTES[32] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
};

// ===========================================================================
// ECDH
// ===========================================================================
static void rct_ecdh_hash(const uint8_t k[32], uint8_t out[32]) {
    uint8_t buf[38];
    memcpy(buf, "amount", 6);
    memcpy(buf + 6, k, 32);
    cn_fast_hash(buf, 38, (char*)out);
}

static void rct_xor8(uint8_t v[32], const uint8_t k[32]) {
    for (int i = 0; i < 8; i++) v[i] ^= k[i];
}

static void rct_gen_commitment_mask(const uint8_t sk[32], uint8_t out[32]) {
    uint8_t buf[15 + 32];
    memcpy(buf, "commitment_mask", 15);
    memcpy(buf + 15, sk, 32);
    cn_fast_hash(buf, sizeof(buf), (char*)out);
    sc_reduce32(out);
}

static void rct_ecdh_encode_v2(const uint8_t shared_sec[32],
                               const uint8_t amount_bytes[32],
                               rct_ecdh_tuple *out)
{
    memset(out->mask.b, 0, 32);

    uint8_t hash[32];
    rct_ecdh_hash(shared_sec, hash);
    memcpy(out->amount.b, amount_bytes, 32);
    rct_xor8(out->amount.b, hash);

    memset(out->amount.b + 8, 0, 24);
}

static void rct_derivation_to_scalar(const uint8_t derivation[32],
                                     size_t output_index,
                                     uint8_t out[32])
{
    uint8_t buf[32 + 10];
    memcpy(buf, derivation, 32);
    size_t vlen = put_varint(buf + 32, output_index);
    cn_fast_hash(buf, 32 + vlen, (char*)out);
    sc_reduce32(out);
}

// ===========================================================================
// rct_generate_tx_key
// ===========================================================================
void rct_generate_tx_key(rct_sig_ctx_t *ctx,
                         const uint8_t tx_secret_key[32],
                         bool use_subaddr,
                         const rct_key *spend_pub)
{
    memcpy(ctx->tx_secret_key, tx_secret_key, 32);
    log_hex32("rct: tx_secret_key (from caller)", ctx->tx_secret_key);

    if (use_subaddr && spend_pub) {
        ge_p3 D_p3;
        if (ge_frombytes_vartime(&D_p3, spend_pub->b) != 0) {
            logf_("rct: spend_pub not on curve");
            memset(ctx->tx_pub_key.b, 0, 32);
            return;
        }
        ge_p2 R_p2;
        ge_scalarmult(&R_p2, ctx->tx_secret_key, &D_p3);
        ge_tobytes(ctx->tx_pub_key.b, &R_p2);
    } else {
        ge_p3 R_p3;
        ge_scalarmult_base(&R_p3, ctx->tx_secret_key);
        ge_p3_tobytes(ctx->tx_pub_key.b, &R_p3);
    }

    log_hex32("rct: tx_pub_key", ctx->tx_pub_key.b);
}

// ===========================================================================
// rct_generate_outputs
// ===========================================================================
bool rct_generate_outputs(rct_sig_ctx_t *ctx,
                          const rct_output_t *outputs,
                          uint32_t n_outputs,
                          const uint8_t (*derivations)[32])
{
    if (n_outputs > RCT_MAX_OUTPUTS) return false;
    if (!derivations) {
        logf_("rct: derivations == NULL");
        return false;
    }

    ctx->base.type      = RCT_TYPE_BULLETPROOF_PLUS;
    ctx->base.n_outputs = n_outputs;

    for (uint32_t i = 0; i < n_outputs; i++) {
        const rct_output_t *o = &outputs[i];

        // === ИСПРАВЛЕНО ===
        // derivation берём ровно ту, от которой в prefix посчитан ключ выхода:
        //   обычный получатель   -> 8*r*A
        //   сдача на свой адрес  -> 8*a*R
        //   субадрес при additional_txkeys -> 8*r_i*C
        // Считать её здесь второй раз нельзя — именно на этом расхождении
        // выходы получались неопознаваемыми.
        const uint8_t *deriv = derivations[i];
        log_hex32("rct: deriv_i", deriv);

        uint8_t scalar[32];
        rct_derivation_to_scalar(deriv, i, scalar);
        log_hex32("rct: scalar_i", scalar);

        uint8_t mask[32];
        rct_gen_commitment_mask(scalar, mask);
        log_hex32("rct: mask_i", mask);
        memcpy(ctx->out_masks[i], mask, 32);

        uint8_t amount_key[32];
        memset(amount_key, 0, 32);
        memcpy(amount_key, &o->amount, 8);
        log_hex32("rct: amount_le", amount_key);

        ge_p2 commit_p2;
        ge_p3 H_p3;
        if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) {
            logf_("rct: H not on curve");
            return false;
        }
        ge_double_scalarmult_base_vartime(&commit_p2, amount_key, &H_p3, mask);
        ge_tobytes(ctx->base.out_pk[i].mask.b, &commit_p2);
        log_hex32("rct: outPk[i].mask", ctx->base.out_pk[i].mask.b);

        rct_ecdh_encode_v2(scalar, amount_key, &ctx->base.ecdh_info[i]);
        log_hex32("rct: ecdhInfo[i].amount", ctx->base.ecdh_info[i].amount.b);

        memcpy(ctx->base.out_pk[i].dest.b, o->dest.b, 32);
    }

    return true;
}

// ===========================================================================
// rct_generate_pseudo_outs
// ===========================================================================
bool rct_generate_pseudo_outs(rct_sig_ctx_t *ctx,
                              const rct_input_t *inputs,
                              uint32_t n_inputs,
                              uint64_t fee)
{
    if (n_inputs > RCT_MAX_INPUTS) return false;

    ctx->base.n_inputs = n_inputs;
    ctx->base.txn_fee  = fee;

    logf_("pseudo_outs: set n_inputs=%u, txn_fee=%llu (0x%llx)",
          (unsigned)n_inputs,
          (unsigned long long)fee,
          (unsigned long long)fee);

    ge_p3 H_p3;
    if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) return false;

    uint8_t sum_a[32];
    memset(sum_a, 0, 32);

    for (uint32_t j = 0; j + 1 < n_inputs; j++) {
        uint8_t a[32];
        platform_random_bytes(a, 32);
        sc_reduce32(a);

        memcpy(ctx->pseudo_outs_priv[j], a, 32);
        sc_add(sum_a, sum_a, a);

        uint8_t amount_key[32];
        memset(amount_key, 0, 32);
        memcpy(amount_key, &inputs[j].amount, 8);

        ge_p2 p2;
        ge_double_scalarmult_base_vartime(&p2, amount_key, &H_p3, a);
        ge_tobytes(ctx->base.pseudo_outs[j].b, &p2);

        char b[100];
        int n = snprintf(b, sizeof(b), "rct: pseudoOut[%u]=", j);
        for (int k = 0; k < 32; k++) n += snprintf(b + n, sizeof(b) - n, "%02x", ctx->base.pseudo_outs[j].b[k]);
        platform_log(b);
    }

    uint8_t sum_masks[32];
    memset(sum_masks, 0, 32);
    for (uint32_t i = 0; i < ctx->base.n_outputs; i++) {
        sc_add(sum_masks, sum_masks, ctx->out_masks[i]);
    }

    uint8_t a_last[32];
    sc_sub(a_last, sum_masks, sum_a);

    uint32_t last = n_inputs - 1;
    memcpy(ctx->pseudo_outs_priv[last], a_last, 32);

    uint8_t amount_last[32];
    memset(amount_last, 0, 32);
    memcpy(amount_last, &inputs[last].amount, 8);

    ge_p2 p2_last;
    ge_double_scalarmult_base_vartime(&p2_last, amount_last, &H_p3, a_last);
    ge_tobytes(ctx->base.pseudo_outs[last].b, &p2_last);

    char b[100];
    int n = snprintf(b, sizeof(b), "rct: pseudoOut[%u]=", last);
    for (int k = 0; k < 32; k++) n += snprintf(b + n, sizeof(b) - n, "%02x", ctx->base.pseudo_outs[last].b[k]);
    platform_log(b);

    logf_("pseudo_outs: END txn_fee=%llu (0x%llx)",
          (unsigned long long)ctx->base.txn_fee,
          (unsigned long long)ctx->base.txn_fee);

    return true;
}

// ===========================================================================
// rct_serialize_sig_base
// ===========================================================================
// rctSigBase для RCTTypeBulletproofPlus:
//   type       : u8
//   txnFee     : varint
//   ecdhInfo   : n_outputs × 8 байт (v2, amount закодирован)
//   outPk.mask : n_outputs × 32 байта
//
size_t rct_serialize_sig_base(const rct_sig_ctx_t *ctx,
                              uint8_t *out_buf, size_t out_cap)
{
    size_t pos = 0;

    #define EMIT_BYTE(b) do { if (pos + 1 > out_cap) return 0; out_buf[pos++] = (b); } while(0)
    #define EMIT_BYTES(p, n) do { if (pos + (n) > out_cap) return 0; memcpy(out_buf + pos, (p), (n)); pos += (n); } while(0)

    logf_("serialize_base: ENTER type=%u txn_fee=%llu (0x%llx) n_outputs=%u n_inputs=%u",
          (unsigned)ctx->base.type,
          (unsigned long long)ctx->base.txn_fee,
          (unsigned long long)ctx->base.txn_fee,
          (unsigned)ctx->base.n_outputs,
          (unsigned)ctx->base.n_inputs);

    EMIT_BYTE(ctx->base.type);

    {
        uint8_t tmp[10];
        size_t n = put_varint(tmp, ctx->base.txn_fee);

        {
            char hexbuf[64];
            int hp = 0;
            for (size_t k = 0; k < n; k++) {
                hp += snprintf(hexbuf + hp, sizeof(hexbuf) - hp, "%02x", tmp[k]);
            }
            logf_("serialize_base: txn_fee=%llu -> varint[%u]=%s",
                  (unsigned long long)ctx->base.txn_fee, (unsigned)n, hexbuf);
        }

        EMIT_BYTES(tmp, n);
    }

    for (uint32_t i = 0; i < ctx->base.n_outputs; i++) {
        EMIT_BYTES(ctx->base.ecdh_info[i].amount.b, 8);
    }

    for (uint32_t i = 0; i < ctx->base.n_outputs; i++) {
        EMIT_BYTES(ctx->base.out_pk[i].mask.b, 32);
    }

    #undef EMIT_BYTE
    #undef EMIT_BYTES

    logf_("serialize_base: EXIT pos=%u", (unsigned)pos);
    return pos;
}

// ===========================================================================
// rct_get_pre_mlsag_hash
// ===========================================================================
bool rct_get_pre_mlsag_hash(const rct_sig_ctx_t *ctx,
                            const uint8_t prefix_hash[32],
                            const uint8_t bp_hash[32],
                            uint8_t full_message_out[32])
{
    uint8_t base_buf[4096];
    size_t base_len = rct_serialize_sig_base(ctx, base_buf, sizeof(base_buf));
    if (base_len == 0) {
        logf_("rct: serialize rctSigBase failed");
        return false;
    }
    logf_("rct: rctSigBase len=%u", (unsigned)base_len);

    uint8_t h1[32];
    cn_fast_hash(base_buf, base_len, (char*)h1);
    log_hex32("rct: h1 (rctSigBase)", h1);

    uint8_t h2[32];
    if (bp_hash) {
        memcpy(h2, bp_hash, 32);
    } else {
        memset(h2, 0, 32);
        logf_("rct: WARNING h2=0");
    }
    log_hex32("rct: h2 (bulletproofs)", h2);

    // === ИСПРАВЛЕНО ===
    // Monero rctSigs.cpp::get_pre_mlsag_hash:
    //   hashes = { message, H(rctSigBase), H(bulletproofs) }
    //   full_message = cn_fast_hash(hashes)   <-- ОДИН keccak по 96 байтам
    // (было: вложенное H(H(message||h1)||h2) — подпись шла по чужому сообщению)
    uint8_t triple_buf[96];
    memcpy(triple_buf,      prefix_hash, 32);
    memcpy(triple_buf + 32, h1,          32);
    memcpy(triple_buf + 64, h2,          32);
    cn_fast_hash(triple_buf, 96, (char*)full_message_out);
    log_hex32("rct: full_message", full_message_out);

    return true;
}

// ===========================================================================
// rct_check_balance
// ===========================================================================
bool rct_check_balance(const rct_sig_ctx_t *ctx)
{
    logf_("check_balance: ENTER txn_fee=%llu (0x%llx) n_inputs=%u n_outputs=%u",
          (unsigned long long)ctx->base.txn_fee,
          (unsigned long long)ctx->base.txn_fee,
          (unsigned)ctx->base.n_inputs,
          (unsigned)ctx->base.n_outputs);

    ge_p3 H_p3;
    if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) {
        logf_("rct_balance: H not on curve");
        return false;
    }

    ge_p3 sum_pseudo;
    fe_0(sum_pseudo.X); fe_1(sum_pseudo.Y);
    fe_1(sum_pseudo.Z); fe_0(sum_pseudo.T);

    for (uint32_t j = 0; j < ctx->base.n_inputs; j++) {
        ge_p3 P;
        if (ge_frombytes_vartime(&P, ctx->base.pseudo_outs[j].b) != 0) {
            logf_("rct_balance: pseudoOut[%u] not on curve", j);
            return false;
        }
        ge_cached Pc;
        ge_p3_to_cached(&Pc, &P);
        ge_p1p1 sum;
        ge_add(&sum, &sum_pseudo, &Pc);
        ge_p1p1_to_p3(&sum_pseudo, &sum);
    }

    ge_p3 sum_out;
    fe_0(sum_out.X); fe_1(sum_out.Y);
    fe_1(sum_out.Z); fe_0(sum_out.T);

    for (uint32_t i = 0; i < ctx->base.n_outputs; i++) {
        ge_p3 P;
        if (ge_frombytes_vartime(&P, ctx->base.out_pk[i].mask.b) != 0) {
            logf_("rct_balance: outPk[%u].mask not on curve", i);
            return false;
        }
        ge_cached Pc;
        ge_p3_to_cached(&Pc, &P);
        ge_p1p1 sum;
        ge_add(&sum, &sum_out, &Pc);
        ge_p1p1_to_p3(&sum_out, &sum);
    }

    uint8_t fee_key[32];
    memset(fee_key, 0, 32);
    memcpy(fee_key, &ctx->base.txn_fee, 8);

    log_hex32("check_balance: fee_key (LE)", fee_key);

    uint8_t zero32[32] = {0};
    ge_p2 feeH_p2;
    ge_double_scalarmult_base_vartime(&feeH_p2, fee_key, &H_p3, zero32);

    uint8_t feeH_bytes[32];
    ge_tobytes(feeH_bytes, &feeH_p2);
    ge_p3 feeH_p3;
    if (ge_frombytes_vartime(&feeH_p3, feeH_bytes) != 0) {
        logf_("rct_balance: feeH not on curve");
        return false;
    }

    ge_cached feeH_c;
    ge_p3_to_cached(&feeH_c, &feeH_p3);
    ge_p1p1 tmp1;
    ge_add(&tmp1, &sum_out, &feeH_c);
    ge_p3 sum_out_plus_fee;
    ge_p1p1_to_p3(&sum_out_plus_fee, &tmp1);

    ge_cached sof_c;
    ge_p3_to_cached(&sof_c, &sum_out_plus_fee);
    ge_p1p1 tmp2;
    ge_sub(&tmp2, &sum_pseudo, &sof_c);
    ge_p3 LHS;
    ge_p1p1_to_p3(&LHS, &tmp2);

    uint8_t bytes[32];
    ge_p3_tobytes(bytes, &LHS);
    log_hex32("rct_balance: LHS", bytes);

    static const uint8_t id_bytes[32] = {
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    if (memcmp(bytes, id_bytes, 32) == 0) {
        logf_("rct_balance: OK");
        return true;
    }
    logf_("rct_balance: FAIL");
    return false;
}

// ===========================================================================
// rct_serialize_sig_prunable_bp_only
// ===========================================================================
// Хеширует A, A1, B, r1, s1, d1, L[], R[] БЕЗ varint(nbp).
// Используется для h2 = H(rctSigPrunable_bp_only).
//
size_t rct_serialize_sig_prunable_bp_only(const bp_plus_proof_t *bp,
                                          uint8_t *out_buf, size_t out_cap)
{
    size_t pos = 0;

    #define EMIT_BYTES(p, n) do { if (pos + (n) > out_cap) return 0; \
                                  memcpy(out_buf + pos, (p), (n)); pos += (n); } while(0)

    EMIT_BYTES(bp->A, 32);
    EMIT_BYTES(bp->A1, 32);
    EMIT_BYTES(bp->B, 32);
    EMIT_BYTES(bp->r1, 32);
    EMIT_BYTES(bp->s1, 32);
    EMIT_BYTES(bp->d1, 32);

    for (uint32_t i = 0; i < bp->n_LR; i++) {
        EMIT_BYTES(bp->L[i], 32);
    }
    for (uint32_t i = 0; i < bp->n_LR; i++) {
        EMIT_BYTES(bp->R[i], 32);
    }

    #undef EMIT_BYTES
    return pos;
}

// ===========================================================================
// rct_serialize_sig_prunable
// ===========================================================================
// === ИСПРАВЛЕНО ===
// Порядок для RCTTypeBulletproofPlus из rctTypes.h::rctSigPrunable:
//   1) varint(nbp) + bulletproofs_plus[i]
//   2) CLSAGs
//   3) pseudoOuts
//
// (В структуре rctSigPrunable CLSAGs объявлено ДО pseudoOuts, и сериализация
// идёт в порядке объявления полей.)
//
size_t rct_serialize_sig_prunable(const rct_sig_ctx_t *ctx,
                                  const bp_plus_proof_t *bp,
                                  uint32_t n_inputs,
                                  uint32_t n_ring,
                                  uint8_t *out_buf, size_t out_cap)
{
    size_t pos = 0;

    #define EMIT_BYTES(p, n) do { if (pos + (n) > out_cap) return 0; \
                                  memcpy(out_buf + pos, (p), (n)); pos += (n); } while(0)
    #define EMIT_VARINT(v) do { \
        uint8_t _tmp[10]; \
        size_t _n = put_varint(_tmp, (v)); \
        EMIT_BYTES(_tmp, _n); \
    } while(0)

    // ============================================================
    // 1. Bulletproofs+
    // ============================================================
    EMIT_VARINT(1);   // nbp = 1

    EMIT_BYTES(bp->A, 32);
    EMIT_BYTES(bp->A1, 32);
    EMIT_BYTES(bp->B, 32);
    EMIT_BYTES(bp->r1, 32);
    EMIT_BYTES(bp->s1, 32);
    EMIT_BYTES(bp->d1, 32);

    EMIT_VARINT(bp->n_LR);
    for (uint32_t i = 0; i < bp->n_LR; i++) EMIT_BYTES(bp->L[i], 32);

    EMIT_VARINT(bp->n_LR);
    for (uint32_t i = 0; i < bp->n_LR; i++) EMIT_BYTES(bp->R[i], 32);

    // ============================================================
    // 2. CLSAGs — ИДУТ ПЕРВЫМИ (до pseudoOuts)
    // ============================================================
    for (uint32_t i = 0; i < n_inputs; i++) {
        const clsag_t *sig = &ctx->clsags[i];

        // s[]: n_ring × 32, БЕЗ varint
        for (uint32_t j = 0; j < n_ring; j++) {
            EMIT_BYTES(sig->s[j], 32);
        }

        EMIT_BYTES(sig->c1, 32);
        EMIT_BYTES(sig->D, 32);
    }

    // ============================================================
    // 3. pseudoOuts — ИДУТ ПОСЛЕ CLSAGs
    // ============================================================
    for (uint32_t j = 0; j < n_inputs; j++) {
        EMIT_BYTES(ctx->base.pseudo_outs[j].b, 32);
    }

    #undef EMIT_BYTES
    #undef EMIT_VARINT

    return pos;
}