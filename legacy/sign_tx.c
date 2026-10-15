// sign_tx.c
//
// Вторая стадия подписи Monero-транзакции.
// Порядок: prefix → rctSigBase → BP+ → h2 → full_message → CLSAG → serialize.

#include "tx_parser.h"
#include "unsigned_tx_set.h"
#include "monero_crypto.h"
#include "sign_tx_construct.h"
#include "rct_sig_construct.h"
#include "clsag.h"
#include "bp_plus.h"

#include <Arduino.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

#include "esp_heap_caps.h"

#include "crypto-ops.h"

// ---- Внешние функции ----
extern void platform_log(const char *msg);
extern void platform_random_bytes(uint8_t *buf, size_t n);
extern void cn_fast_hash(const void *data, size_t length, char *hash);

// ---- Диагностика ----
static void diag(const char *fmt, ...) {
    char buf[200];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    platform_log(buf);
}

static void diag_hex32(const char *prefix, const uint8_t *p) {
    char buf[100];
    int n = snprintf(buf, sizeof(buf), "%s=", prefix);
    for (int i = 0; i < 32; i++) n += snprintf(buf + n, sizeof(buf) - n, "%02x", p[i]);
    platform_log(buf);
}

// H = toPoint(cn_fast_hash(G))
static const uint8_t H_BYTES_LOCAL[32] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
};

// INV_EIGHT = 8^(-1) mod l
static const uint8_t INV_EIGHT_LOCAL[32] = {
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
    0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06
};

// l (порядок подгруппы ed25519)
static const uint8_t L_SCALAR[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

// ===========================================================================
// ГЛОБАЛЬНЫЕ БУФЕРЫ
// ===========================================================================
static unsigned_tx_set_t *g_uts = NULL;
static tx_parsed_t       *g_tx  = NULL;

static rct_sig_ctx_t g_rct_ctx;
static rct_output_t  g_rct_outs[RCT_MAX_OUTPUTS];
static rct_input_t   g_rct_ins[RCT_MAX_INPUTS];

static bp_plus_proof_t g_bp_proof;

static uint8_t g_sig_base_buf[4096];
static uint8_t g_sig_prunable_buf[16384];

static void *psram_alloc(size_t sz) {
    return heap_caps_malloc(sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

static bool is_unsigned_tx_set(const uint8_t *in, size_t in_len) {
    static const char magic[] = "Monero unsigned tx set";
    const size_t magic_len = sizeof(magic) - 1;
    if (in_len < magic_len + 1) return false;
    if (memcmp(in, magic, magic_len) != 0) return false;
    return true;
}

// ===========================================================================
// ← ДОБАВЛЕНО: проверка точки на подгруппе порядка l
// ===========================================================================
// Проверяет: l * P == identity. Возвращает true, если точка в подгруппе.
// Логирует результат.
static bool check_point_in_subgroup(const char *name, const uint8_t P_bytes[32]) {
    ge_p3 P;
    if (ge_frombytes_vartime(&P, P_bytes) != 0) {
        diag("SUBGROUP: %s NOT ON CURVE", name);
        diag_hex32("  point", P_bytes);
        return false;
    }
    if (ge_p3_is_point_at_infinity_vartime(&P)) {
        diag("SUBGROUP: %s IS IDENTITY", name);
        return false;
    }
    // Умножаем на l
    ge_p2 R;
    ge_scalarmult(&R, L_SCALAR, &P);
    uint8_t R_bytes[32];
    ge_tobytes(R_bytes, &R);
    // Проверяем, что R — identity
    ge_p3 R_p3;
    if (ge_frombytes_vartime(&R_p3, R_bytes) != 0) {
        // Может быть identity не парсится — сравним с каноничным identity
        static const uint8_t ID[32] = {1};
        if (memcmp(R_bytes, ID, 32) != 0) {
            diag("SUBGROUP: %s NOT in subgroup (l*P != identity)", name);
            diag_hex32("  P", P_bytes);
            diag_hex32("  l*P", R_bytes);
            return false;
        }
        diag("SUBGROUP: %s in subgroup OK (identity via bytes)", name);
        return true;
    }
    if (!ge_p3_is_point_at_infinity_vartime(&R_p3)) {
        diag("SUBGROUP: %s NOT in subgroup (l*P != identity)", name);
        diag_hex32("  P", P_bytes);
        diag_hex32("  l*P", R_bytes);
        return false;
    }
    diag("SUBGROUP: %s in subgroup OK", name);
    return true;
}

// ===========================================================================
// ← ДОБАВЛЕНО: проверка всех точек транзакции на подгруппе
// ===========================================================================
static void check_all_tx_points_in_subgroup(void) {
    diag("=== SUBGROUP CHECK: все точки транзакции ===");
    int total_ok = 0;
    int total_bad = 0;

    // H
    if (check_point_in_subgroup("H", H_BYTES_LOCAL)) total_ok++; else total_bad++;

    // outPk[i].mask
    for (uint32_t i = 0; i < g_rct_ctx.base.n_outputs; i++) {
        char name[32];
        snprintf(name, sizeof(name), "outPk[%u].mask", i);
        if (check_point_in_subgroup(name, g_rct_ctx.base.out_pk[i].mask.b)) total_ok++;
        else total_bad++;
    }

    // pseudoOuts[j]
    for (uint32_t j = 0; j < g_rct_ctx.base.n_inputs; j++) {
        char name[32];
        snprintf(name, sizeof(name), "pseudoOut[%u]", j);
        if (check_point_in_subgroup(name, g_rct_ctx.base.pseudo_outs[j].b)) total_ok++;
        else total_bad++;
    }

    // V[i]
    for (uint32_t i = 0; i < g_bp_proof.n_V; i++) {
        char name[32];
        snprintf(name, sizeof(name), "V[%u]", i);
        if (check_point_in_subgroup(name, g_bp_proof.V[i])) total_ok++;
        else total_bad++;
    }

    // A, A1, B
    if (check_point_in_subgroup("BP+.A",  g_bp_proof.A))  total_ok++; else total_bad++;
    if (check_point_in_subgroup("BP+.A1", g_bp_proof.A1)) total_ok++; else total_bad++;
    if (check_point_in_subgroup("BP+.B",  g_bp_proof.B))  total_ok++; else total_bad++;

    // L[i], R[i]
    for (uint32_t i = 0; i < g_bp_proof.n_LR; i++) {
        char nameL[32], nameR[32];
        snprintf(nameL, sizeof(nameL), "BP+.L[%u]", i);
        snprintf(nameR, sizeof(nameR), "BP+.R[%u]", i);
        if (check_point_in_subgroup(nameL, g_bp_proof.L[i])) total_ok++; else total_bad++;
        if (check_point_in_subgroup(nameR, g_bp_proof.R[i])) total_ok++; else total_bad++;
    }

    // CLSAG I, D, c1 (I, D — точки; c1 — скаляр, не проверяем подгруппу)
    for (uint32_t j = 0; j < g_rct_ctx.base.n_inputs; j++) {
        char nameI[32], nameD[32];
        snprintf(nameI, sizeof(nameI), "CLSAG[%u].I", j);
        snprintf(nameD, sizeof(nameD), "CLSAG[%u].D", j);
        if (check_point_in_subgroup(nameI, g_rct_ctx.clsags[j].I)) total_ok++; else total_bad++;
        if (check_point_in_subgroup(nameD, g_rct_ctx.clsags[j].D)) total_ok++; else total_bad++;
    }

    diag("=== SUBGROUP CHECK DONE: ok=%d bad=%d ===", total_ok, total_bad);
}

// ===========================================================================
// Проверка outPk[i].mask == mask_i*G + amount_i*H
// ===========================================================================
static bool check_outpk_mask(uint32_t i, const rct_output_t *o) {
    ge_p3 maskG_p3;
    ge_scalarmult_base(&maskG_p3, g_rct_ctx.out_masks[i]);

    ge_p3 H_p3;
    if (ge_frombytes_vartime(&H_p3, H_BYTES_LOCAL) != 0) {
        diag("check_outpk: H not on curve");
        return false;
    }

    uint8_t amount_le[32] = {0};
    memcpy(amount_le, &o->amount, 8);
    ge_p2 amountH_p2;
    ge_scalarmult(&amountH_p2, amount_le, &H_p3);
    uint8_t amountH_b[32];
    ge_tobytes(amountH_b, &amountH_p2);
    ge_p3 amountH_p3;
    if (ge_frombytes_vartime(&amountH_p3, amountH_b) != 0) {
        diag("check_outpk: amountH not on curve");
        return false;
    }

    ge_cached amountH_c;
    ge_p3_to_cached(&amountH_c, &amountH_p3);
    ge_p1p1 sum_p1p1;
    ge_add(&sum_p1p1, &maskG_p3, &amountH_c);
    ge_p3 sum_p3;
    ge_p1p1_to_p3(&sum_p3, &sum_p1p1);
    uint8_t sum_b[32];
    ge_p3_tobytes(sum_b, &sum_p3);

    if (memcmp(sum_b, g_rct_ctx.base.out_pk[i].mask.b, 32) == 0) {
        diag("outPk[%u].mask == mask*G + amount*H  OK", (unsigned)i);
        return true;
    } else {
        diag("outPk[%u].mask != mask*G + amount*H  FAIL", (unsigned)i);
        diag_hex32("  calc  ", sum_b);
        diag_hex32("  outPk ", g_rct_ctx.base.out_pk[i].mask.b);
        diag_hex32("  mask_i", g_rct_ctx.out_masks[i]);
        return false;
    }
}

// ===========================================================================
// Полный hex-дамп
// ===========================================================================
static void dump_tx_hex(const uint8_t *tx, size_t tx_len) {
    const size_t CHUNK = 60;
    char line[256];

    diag("TX_HEX_BEGIN len=%u", (unsigned)tx_len);

    for (size_t off = 0; off < tx_len; off += CHUNK) {
        size_t chunk = tx_len - off;
        if (chunk > CHUNK) chunk = CHUNK;

        int p = snprintf(line, sizeof(line), "TX_HEX %04x: ", (unsigned)off);
        for (size_t i = 0; i < chunk && p + 3 < (int)sizeof(line); i++) {
            p += snprintf(line + p, sizeof(line) - p, "%02x", tx[off + i]);
        }
        platform_log(line);
    }

    diag("TX_HEX_END");
}

// ===========================================================================
// Ветка unsigned_tx_set v5
// ===========================================================================
static bool sign_unsigned_tx_set(const uint8_t *in, size_t in_len,
                                 uint8_t *tx_out, size_t tx_out_cap,
                                 size_t *tx_out_len)
{
    const size_t magic_len = strlen("Monero unsigned tx set");
    if (in_len < magic_len + 1) {
        platform_log("sign_transaction: truncated unsigned_tx_set");
        return false;
    }

    const uint8_t version_byte = in[magic_len];
    diag("sign_transaction: version byte = 0x%02x", version_byte);
    if (version_byte != 0x05) {
        diag("sign_transaction: unsupported version 0x%02x", version_byte);
        return false;
    }

    const uint8_t *payload = in + magic_len + 1;
    const size_t payload_len = in_len - magic_len - 1;

    if (!g_uts) {
        diag("sign_transaction: allocating uts in PSRAM (size=%u)",
             (unsigned)sizeof(unsigned_tx_set_t));
        g_uts = (unsigned_tx_set_t *)psram_alloc(sizeof(unsigned_tx_set_t));
        if (!g_uts) {
            platform_log("sign_transaction: PSRAM alloc FAILED for uts");
            return false;
        }
    }

    extern uint8_t g_view_secret_key[32];

    platform_log("sign_transaction: parsing unsigned_tx_set...");
    if (!uts_parse_encrypted(payload, payload_len,
                             g_view_secret_key, g_uts)) {
        platform_log("sign_transaction: uts_parse FAILED");
        return false;
    }

    uts_dump(g_uts);

    // === ДОБАВЛЕНО ===
    // Кошелёк разбивает крупный перевод на несколько транзакций, и тогда в
    // unsigned set их больше одной. Подписывается здесь только txes[0], поэтому
    // молча продолжать нельзя: пользователь отправит первую и будет считать,
    // что отправил всё.
    if (g_uts->n_txes != 1) {
        diag("sign_transaction: в unsigned set %u транзакций, поддерживается ровно одна",
             (unsigned)g_uts->n_txes);
        diag("sign_transaction: разбейте перевод на отдельные переводы в кошельке");
        return false;
    }

    // ===== tx_secret_key =====
    static uint8_t g_tx_secret_key[32];
    platform_random_bytes(g_tx_secret_key, 32);
    sc_reduce32(g_tx_secret_key);

    char skb[68];
    for (int b = 0; b < 32; b++) sprintf(skb + b*2, "%02x", g_tx_secret_key[b]);
    skb[64] = 0;
    diag("sign_transaction: tx_secret_key=%s", skb);

    // ===== plaintext =====
    size_t plain_len = 0;
    const uint8_t *plain = uts_get_last_plain(&plain_len);
    diag("sign_transaction: raw plain ptr=%p len=%u",
         (const void*)plain, (unsigned)plain_len);
    sign_set_raw_plain(plain, plain_len);

    // ===== prefix + prefix_hash =====
    static uint8_t g_prefix_buf[8192];
    static uint8_t g_prefix_hash[32];

    size_t plen = sign_build_prefix(g_uts,
                                    g_tx_secret_key,
                                    NULL, 0,
                                    g_prefix_buf, sizeof(g_prefix_buf),
                                    g_prefix_hash);
    if (plen == 0) {
        platform_log("sign_transaction: sign_build_prefix FAILED");
        return false;
    }

    diag("sign_transaction: prefix_len=%u", (unsigned)plen);

    char phb[68];
    for (int b = 0; b < 32; b++) sprintf(phb + b*2, "%02x", g_prefix_hash[b]);
    phb[64] = 0;
    diag("sign_transaction: prefix_hash=%s", phb);

    // =======================================================================
    // RCT base
    // =======================================================================
    memset(&g_rct_ctx, 0, sizeof(g_rct_ctx));

    // ----- use_subaddr -----
    bool use_subaddr = false;
    rct_key spend_pub_for_subaddr;
    memset(&spend_pub_for_subaddr, 0, sizeof(spend_pub_for_subaddr));

    {
        // === ИСПРАВЛЕНО ===
        // Используем тот же классификатор, что и sign_build_prefix
        // (порт classify_addresses: адрес сдачи в подсчёте не участвует).
        bool need_additional = false;
        uint8_t single_sub_D[32];
        sign_classify_dsts(&g_uts->txes[0], &use_subaddr,
                           single_sub_D, &need_additional);
        if (use_subaddr) {
            memcpy(spend_pub_for_subaddr.b, single_sub_D, 32);
            diag("rct: single subaddress destination → use_subaddr=true");
        } else {
            diag("rct: use_subaddr=false");
        }
    }

    // ----- tx_key -----
    rct_generate_tx_key(&g_rct_ctx, g_tx_secret_key, use_subaddr,
                        use_subaddr ? &spend_pub_for_subaddr : NULL);

    // ----- outPk[i].mask + ecdhInfo[i] -----
    uint32_t n_outs = (uint32_t)g_uts->txes[0].n_splitted_dsts;
    if (n_outs == 0 || n_outs > RCT_MAX_OUTPUTS) {
        diag("sign_transaction: invalid n_outs=%u", (unsigned)n_outs);
        return false;
    }
    memset(g_rct_outs, 0, sizeof(g_rct_outs));

    for (uint32_t i = 0; i < n_outs; i++) {
        const uts_tx_destination_entry_t *d = &g_uts->txes[0].splitted_dsts[i];
        memcpy(g_rct_outs[i].dest.b, d->addr.view_public_key, 32);
        g_rct_outs[i].amount = d->amount;
        g_rct_outs[i].is_change = sign_dst_is_change(&g_uts->txes[0], d);
        diag("rct: out[%u] amount=%llu view_pub=%02x%02x%02x%02x..",
             (unsigned)i, (unsigned long long)d->amount,
             d->addr.view_public_key[0], d->addr.view_public_key[1],
             d->addr.view_public_key[2], d->addr.view_public_key[3]);
    }

    // derivations берём из prefix-стадии — там они уже посчитаны с учётом
    // сдачи и additional_tx_keys.
    static uint8_t out_derivs[RCT_MAX_OUTPUTS][32];
    if (sign_get_n_output_derivations() != n_outs) {
        diag("sign_transaction: derivations=%u, ожидалось %u",
             (unsigned)sign_get_n_output_derivations(), (unsigned)n_outs);
        return false;
    }
    for (uint32_t i = 0; i < n_outs; i++) {
        if (!sign_get_output_derivation(i, out_derivs[i])) {
            diag("sign_transaction: sign_get_output_derivation(%u) FAILED", (unsigned)i);
            return false;
        }
    }

    if (!rct_generate_outputs(&g_rct_ctx, g_rct_outs, n_outs, out_derivs)) {
        platform_log("sign_transaction: rct_generate_outputs FAILED");
        return false;
    }

    diag("sign_transaction: base.type=%u, n_outputs=%u, n_inputs=%u, txn_fee=%llu",
         (unsigned)g_rct_ctx.base.type,
         (unsigned)g_rct_ctx.base.n_outputs,
         (unsigned)g_rct_ctx.base.n_inputs,
         (unsigned long long)g_rct_ctx.base.txn_fee);

    diag("sign_transaction: checking outPk.mask == mask*G + amount*H...");
    for (uint32_t i = 0; i < n_outs; i++) {
        check_outpk_mask(i, &g_rct_outs[i]);
    }

    // ----- pseudoOuts[j] -----
    uint32_t n_ins = sign_get_n_sources();
    if (n_ins == 0 || n_ins > RCT_MAX_INPUTS) {
        diag("sign_transaction: invalid n_ins=%u", (unsigned)n_ins);
        return false;
    }
    memset(g_rct_ins, 0, sizeof(g_rct_ins));

    for (uint32_t j = 0; j < n_ins; j++) {
        uts_tx_source_entry_t sorted_src;
        if (!sign_get_sorted_source(j, &sorted_src)) {
            diag("sign_transaction: sign_get_sorted_source(%u) FAILED", (unsigned)j);
            return false;
        }
        g_rct_ins[j].amount = sorted_src.amount;
        g_rct_ins[j].n_ring = sorted_src.n_outputs;
        g_rct_ins[j].real_output = (uint32_t)sorted_src.real_output;
        if (sorted_src.n_outputs > RCT_MAX_RING) {
            diag("sign_transaction: ring too big at src[%u]: %u",
                 (unsigned)j, (unsigned)sorted_src.n_outputs);
            return false;
        }
        for (uint32_t k = 0; k < sorted_src.n_outputs; k++) {
            memcpy(g_rct_ins[j].ring[k].dest.b, sorted_src.outputs[k].ctkey.dest, 32);
            memcpy(g_rct_ins[j].ring[k].mask.b, sorted_src.outputs[k].ctkey.mask, 32);
        }
        diag("rct: in[%u] amount=%llu ring=%u real=%u (sorted)",
             (unsigned)j, (unsigned long long)sorted_src.amount,
             (unsigned)sorted_src.n_outputs, (unsigned)sorted_src.real_output);
    }

    uint64_t fee = 0;
    {
        uint64_t sum_in = 0, sum_out = 0;
        for (uint32_t j = 0; j < n_ins; j++) sum_in += g_rct_ins[j].amount;
        for (uint32_t i = 0; i < n_outs; i++) sum_out += g_rct_outs[i].amount;
        if (sum_in > sum_out) fee = sum_in - sum_out;
        diag("rct: sum_in=%llu sum_out=%llu fee=%llu",
             (unsigned long long)sum_in, (unsigned long long)sum_out,
             (unsigned long long)fee);
    }

    if (!rct_generate_pseudo_outs(&g_rct_ctx, g_rct_ins, n_ins, fee)) {
        platform_log("sign_transaction: rct_generate_pseudo_outs FAILED");
        return false;
    }

    // =======================================================================
    // ← ДОБАВЛЕНО: проверка подгруппы для outPk.mask и pseudoOuts
    // =======================================================================
    diag("=== SUBGROUP CHECK: outPk.mask и pseudoOuts ===");
    for (uint32_t i = 0; i < n_outs; i++) {
        char name[32];
        snprintf(name, sizeof(name), "outPk[%u].mask", i);
        check_point_in_subgroup(name, g_rct_ctx.base.out_pk[i].mask.b);
    }
    for (uint32_t j = 0; j < n_ins; j++) {
        char name[32];
        snprintf(name, sizeof(name), "pseudoOut[%u]", j);
        check_point_in_subgroup(name, g_rct_ctx.base.pseudo_outs[j].b);
    }
    diag("=== SUBGROUP CHECK outPk/pseudoOuts DONE ===");

    // =======================================================================
    // ШАГ 1: Bulletproofs+ (ДО CLSAG!)
    // =======================================================================
    platform_log("sign_transaction: generating Bulletproofs+ (step 1)...");

    uint64_t amounts_buf[RCT_MAX_OUTPUTS];
    uint8_t  gammas_buf[RCT_MAX_OUTPUTS][32];
    for (uint32_t i = 0; i < n_outs; i++) {
        amounts_buf[i] = g_rct_outs[i].amount;
        memcpy(gammas_buf[i], g_rct_ctx.out_masks[i], 32);
    }

    memset(&g_bp_proof, 0, sizeof(g_bp_proof));

    uint32_t t_bp = millis();
    if (!bp_plus_prove(amounts_buf, gammas_buf, n_outs, &g_bp_proof)) {
        diag("sign_transaction: bp_plus_prove FAILED");
        return false;
    }
    diag("sign_transaction: BP+ OK, n_V=%u n_LR=%u, took %u ms",
         (unsigned)g_bp_proof.n_V, (unsigned)g_bp_proof.n_LR,
         (unsigned)(millis() - t_bp));

    diag("sign_transaction: checking V[i]*8 == outPk[i].mask...");
    for (uint32_t i = 0; i < n_outs; i++) {
        ge_p3 V_p3;
        if (ge_frombytes_vartime(&V_p3, g_bp_proof.V[i]) != 0) {
            diag("V[%u] not on curve", (unsigned)i);
            continue;
        }
        ge_p2 V8_p2;
        ge_p1p1 V8_p1p1;
        ge_p3_to_p2(&V8_p2, &V_p3);
        ge_mul8(&V8_p1p1, &V8_p2);
        ge_p2 V8_p2b;
        ge_p1p1_to_p2(&V8_p2b, &V8_p1p1);
        uint8_t V8[32];
        ge_tobytes(V8, &V8_p2b);

        if (memcmp(V8, g_rct_ctx.base.out_pk[i].mask.b, 32) == 0) {
            diag("V[%u]*8 == outPk.mask  OK", (unsigned)i);
        } else {
            diag("V[%u]*8 != outPk.mask  FAIL", (unsigned)i);
            diag_hex32("  V*8   ", V8);
            diag_hex32("  outPk ", g_rct_ctx.base.out_pk[i].mask.b);
        }
    }

    diag_hex32("BP+.A",  g_bp_proof.A);
    diag_hex32("BP+.A1", g_bp_proof.A1);
    diag_hex32("BP+.B",  g_bp_proof.B);
    diag_hex32("BP+.r1", g_bp_proof.r1);
    diag_hex32("BP+.s1", g_bp_proof.s1);
    diag_hex32("BP+.d1", g_bp_proof.d1);

    // =======================================================================
    // ШАГ 2: h2 = hash(rctSigPrunable_bp_only)
    // =======================================================================
    static uint8_t g_bp_only_buf[8192];
    size_t bp_only_len = rct_serialize_sig_prunable_bp_only(
        &g_bp_proof, g_bp_only_buf, sizeof(g_bp_only_buf));
    if (bp_only_len == 0) {
        platform_log("sign_transaction: rct_serialize_sig_prunable_bp_only FAILED");
        return false;
    }

    diag("sign_transaction: bp_only_len=%u (expect %u)",
         (unsigned)bp_only_len,
         (unsigned)(6*32 + g_bp_proof.n_LR*32 + g_bp_proof.n_LR*32));

    uint8_t h2[32];
    cn_fast_hash(g_bp_only_buf, bp_only_len, (char*)h2);
    diag_hex32("sign_transaction: h2 (bp_only)", h2);

    // =======================================================================
    // ШАГ 3: full_message = prefix_hash + h1 + h2
    // =======================================================================
    uint8_t full_message[32];
    if (!rct_get_pre_mlsag_hash(&g_rct_ctx, g_prefix_hash, h2, full_message)) {
        platform_log("sign_transaction: rct_get_pre_mlsag_hash FAILED");
        return false;
    }

    rct_check_balance(&g_rct_ctx);

    // =======================================================================
    // ШАГ 4: CLSAG (ПОСЛЕ h2)
    // =======================================================================
    platform_log("sign_transaction: generating CLSAGs (step 4)...");

    for (uint32_t j = 0; j < n_ins; j++) {
        uint8_t x_j[32];
        if (!sign_get_source_x(j, x_j)) {
            diag("sign_transaction: sign_get_source_x(%u) FAILED", (unsigned)j);
            return false;
        }

        // === ИСПРАВЛЕНО ===
        // Monero genRctSimple: z = inSk[j].mask - a[j],
        // где inSk[j].mask — маска коммитмента РЕАЛЬНОГО входа (из uts),
        // a[j] — маска псевдо-выхода.
        // (было: z = a[j], из-за чего z*G != C[l] - C_offset и CLSAG не проверялся)
        uint8_t z_buf[32];
        {
            // static: sizeof(uts_tx_source_entry_t) ~3 КБ — на стек ESP32 не кладём
            static uts_tx_source_entry_t src_j;
            if (!sign_get_sorted_source(j, &src_j)) {
                diag("sign_transaction: sign_get_sorted_source(%u) FAILED (z)", (unsigned)j);
                return false;
            }
            sc_sub(z_buf, src_j.mask, g_rct_ctx.pseudo_outs_priv[j]);
        }
        const uint8_t *z_j = z_buf;
        const uint8_t *C_offset_j = g_rct_ctx.base.pseudo_outs[j].b;

        uint8_t P_buf[RCT_MAX_RING][32];
        uint8_t C_nonzero_buf[RCT_MAX_RING][32];
        for (uint32_t k = 0; k < g_rct_ins[j].n_ring; k++) {
            memcpy(P_buf[k], g_rct_ins[j].ring[k].dest.b, 32);
            memcpy(C_nonzero_buf[k], g_rct_ins[j].ring[k].mask.b, 32);
        }

        uint32_t l = g_rct_ins[j].real_output;
        uint32_t n = g_rct_ins[j].n_ring;

        diag("CLSAG[%u]: n=%u l=%u", (unsigned)j, (unsigned)n, (unsigned)l);

        if (!clsag_prove(full_message,
                         P_buf,
                         C_nonzero_buf,
                         C_offset_j,
                         x_j,
                         z_j,
                         l,
                         n,
                         &g_rct_ctx.clsags[j])) {
            diag("sign_transaction: clsag_prove[%u] FAILED", (unsigned)j);
            return false;
        }

        char ib[68];
        for (int b = 0; b < 32; b++) sprintf(ib + b*2, "%02x", g_rct_ctx.clsags[j].I[b]);
        ib[64] = 0;
        diag("CLSAG[%u]: I=%s", (unsigned)j, ib);
    }

    platform_log("sign_transaction: CLSAGs OK");

    for (uint32_t j = 0; j < n_ins; j++) {
        uint8_t ki_j[32];
        if (sign_get_source_ki(j, ki_j)) {
            if (memcmp(g_rct_ctx.clsags[j].I, ki_j, 32) != 0) {
                diag("sign_transaction: CLSAG[%u].I != ki_j!", (unsigned)j);
                return false;
            }
            diag("sign_transaction: CLSAG[%u].I matches ki", (unsigned)j);
        }
    }

    // =======================================================================
    // ← ДОБАВЛЕНО: проверка подгруппы для всех точек после подписи
    // =======================================================================
    check_all_tx_points_in_subgroup();

    // =======================================================================
    // ДИАГНОСТИКА INV_EIGHT / V[i]
    // =======================================================================
    {
        uint8_t eight[32] = {8};

        uint8_t inv8_x_8[32];
        sc_mul(inv8_x_8, INV_EIGHT_LOCAL, eight);
        diag_hex32("CHECK: INV_EIGHT * 8", inv8_x_8);

        uint8_t mask8[32], restored[32];
        sc_mul(mask8, g_rct_ctx.out_masks[0], INV_EIGHT_LOCAL);
        sc_mul(restored, mask8, eight);
        diag_hex32("CHECK: mask[0]         ", g_rct_ctx.out_masks[0]);
        diag_hex32("CHECK: mask[0]*inv8*8  ", restored);
        if (memcmp(restored, g_rct_ctx.out_masks[0], 32) == 0) {
            diag("CHECK: mask_i roundtrip  OK");
        } else {
            diag("CHECK: mask_i roundtrip  FAIL");
        }

        uint8_t sv[32] = {0}, sv8[32], restored2[32];
        memcpy(sv, &g_rct_outs[0].amount, 8);
        sc_mul(sv8, sv, INV_EIGHT_LOCAL);
        sc_mul(restored2, sv8, eight);
        diag_hex32("CHECK: amount          ", sv);
        diag_hex32("CHECK: amount*inv8*8   ", restored2);
        if (memcmp(restored2, sv, 32) == 0) {
            diag("CHECK: amount roundtrip  OK");
        } else {
            diag("CHECK: amount roundtrip  FAIL");
        }

        uint8_t two[32] = {2}, three[32] = {3}, six[32];
        sc_mul(six, two, three);
        diag_hex32("CHECK: 2*3             ", six);

        {
            uint8_t mask8_local[32], amount8_local[32], amount_le[32];
            sc_mul(mask8_local, g_rct_ctx.out_masks[0], INV_EIGHT_LOCAL);

            memset(amount_le, 0, 32);
            memcpy(amount_le, &g_rct_outs[0].amount, 8);
            sc_mul(amount8_local, amount_le, INV_EIGHT_LOCAL);

            ge_p3 H_p3;
            ge_frombytes_vartime(&H_p3, H_BYTES_LOCAL);

            ge_p2 V_p2_local;
            ge_double_scalarmult_base_vartime(&V_p2_local, amount8_local, &H_p3, mask8_local);

            ge_p1p1 V8_p1p1;
            ge_mul8(&V8_p1p1, &V_p2_local);
            ge_p2 V8_p2;
            ge_p1p1_to_p2(&V8_p2, &V8_p1p1);
            uint8_t V8_local[32];
            ge_tobytes(V8_local, &V8_p2);

            diag_hex32("CHECK: local V*8 (formula)", V8_local);
            diag_hex32("CHECK: outPk[0].mask      ", g_rct_ctx.base.out_pk[0].mask.b);

            if (memcmp(V8_local, g_rct_ctx.base.out_pk[0].mask.b, 32) == 0) {
                diag("CHECK: local formula V*8 == outPk  OK");
            } else {
                diag("CHECK: local formula V*8 != outPk  FAIL");
            }
        }
    }

    // =======================================================================
    // ШАГ 5: сериализация rctSigBase + rctSigPrunable (полный)
    // =======================================================================
    platform_log("sign_transaction: serializing rctSig...");

    uint32_t n_ring = 0;
    for (uint32_t j = 0; j < n_ins; j++) {
        if (g_rct_ins[j].n_ring > n_ring) n_ring = g_rct_ins[j].n_ring;
    }
    diag("sign_transaction: n_ring=%u", (unsigned)n_ring);

    diag("sign_transaction: BEFORE serialize base.type=%u, n_outputs=%u, n_inputs=%u",
         (unsigned)g_rct_ctx.base.type,
         (unsigned)g_rct_ctx.base.n_outputs,
         (unsigned)g_rct_ctx.base.n_inputs);

    size_t base_len = rct_serialize_sig_base(&g_rct_ctx,
                                             g_sig_base_buf, sizeof(g_sig_base_buf));
    if (base_len == 0) {
        platform_log("sign_transaction: rct_serialize_sig_base FAILED");
        return false;
    }
    diag("sign_transaction: rctSigBase len=%u, first byte=0x%02x",
         (unsigned)base_len, (unsigned)g_sig_base_buf[0]);

    size_t prunable_len = rct_serialize_sig_prunable(
        &g_rct_ctx, &g_bp_proof, n_ins, n_ring,
        g_sig_prunable_buf, sizeof(g_sig_prunable_buf));
    if (prunable_len == 0) {
        platform_log("sign_transaction: rct_serialize_sig_prunable FAILED");
        return false;
    }
    diag("sign_transaction: rctSigPrunable len=%u", (unsigned)prunable_len);

    // =======================================================================
    // Сборка финального tx
    // =======================================================================
    size_t tx_len = plen + base_len + prunable_len;
    diag("sign_transaction: tx total = %u (prefix %u + base %u + prunable %u)",
         (unsigned)tx_len, (unsigned)plen, (unsigned)base_len, (unsigned)prunable_len);

    if (tx_len > tx_out_cap) {
        diag("sign_transaction: out buffer too small (%u > %u)",
             (unsigned)tx_len, (unsigned)tx_out_cap);
        return false;
    }

    memcpy(tx_out, g_prefix_buf, plen);
    memcpy(tx_out + plen, g_sig_base_buf, base_len);
    memcpy(tx_out + plen + base_len, g_sig_prunable_buf, prunable_len);
    *tx_out_len = tx_len;

    diag("sign_transaction: tx built, len=%u", (unsigned)tx_len);
    diag("sign_transaction: rct.type at offset %u = 0x%02x",
         (unsigned)plen, (unsigned)tx_out[plen]);

    dump_tx_hex(tx_out, tx_len);

    platform_log("sign_transaction: DONE");
    return true;
}

// ===========================================================================
// Точка входа
// ===========================================================================
bool sign_transaction(const uint8_t *tx_in, size_t tx_in_len,
                      uint8_t *tx_out, size_t tx_out_cap,
                      size_t *tx_out_len)
{
    platform_log("sign_transaction: START");

    if (!tx_in || !tx_out || !tx_out_len) {
        platform_log("sign_transaction: NULL arg");
        return false;
    }
    if (tx_in_len == 0) {
        platform_log("sign_transaction: empty input");
        return false;
    }

    const char *fmt = is_unsigned_tx_set(tx_in, tx_in_len)
                        ? "unsigned_tx_set" : "raw_tx";
    diag("sign_transaction: format=%s, first bytes %02x %02x %02x %02x",
         fmt, tx_in[0], tx_in[1], tx_in[2], tx_in[3]);

    if (is_unsigned_tx_set(tx_in, tx_in_len)) {
        return sign_unsigned_tx_set(tx_in, tx_in_len,
                                    tx_out, tx_out_cap, tx_out_len);
    }

    platform_log("sign_transaction: raw_tx not implemented");
    return false;
}