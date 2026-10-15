// sign_tx_construct.c
//
// Построение prefix транзакции Monero из unsigned_tx_set.
// Плюс сохранение x и отсортированных источников для CLSAG.
//
// === ИСПРАВЛЕНО ===
// 1. Extra берётся из unsigned_tx_set (44 байта), а не строится с нуля.
// 2. Вычисляется dummy encrypted_payment_id (8 байт) и подставляется
//    в extra вместо нулей — как в wallet2.cpp::transfer (Monero v0.18.5.1).
//
//   payment_id8 = null_hash8
//   shared_secret = tx_secret_key * view_public_key
//   key = Keccak(shared_secret || 0x8d)
//   encrypted_payment_id = payment_id8 XOR key[:8]
//
//   В extra формат:  02 09 01 <8 байт encrypted_payment_id>

#include "sign_tx_construct.h"
#include "unsigned_tx_set.h"
#include "crypto-ops.h"
#include "hash-ops.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

extern void platform_log(const char *msg);
extern void cn_fast_hash(const void *data, size_t length, char *hash);
extern bool crypto_generate_key_derivation(const uint8_t tx_pubkey[32],
                                            const uint8_t view_secret_key[32],
                                            uint8_t derivation_out[32]);
extern void crypto_generate_subaddress_secret_key(const uint8_t view_sk[32],
                                                  uint32_t major, uint32_t minor,
                                                  uint8_t out_m[32]);
extern void crypto_secret_key_to_public_key(const uint8_t sec[32], uint8_t pub[32]);
extern void platform_random_bytes(uint8_t *buf, size_t n);
extern uint8_t g_view_secret_key[32];
extern uint8_t g_spend_secret_key[32];
extern uint8_t g_spend_public_key[32];

// ---- Хардкод адреса кошелька ----

static const uint8_t *g_raw_plain = NULL;
static size_t         g_raw_plain_len = 0;

// ===========================================================================
// PSRAM-аллокатор
// ===========================================================================
static void *psram_alloc(size_t sz) {
    return heap_caps_malloc(sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

static void logf_(const char *fmt, ...);

// ===========================================================================
// === ДОБАВЛЕНО: порт cryptonote::classify_addresses() ===
//
// Monero (cryptonote_tx_utils.cpp):
//   - адрес сдачи (change_addr) в подсчёте НЕ участвует;
//   - одинаковые адреса считаются один раз (unordered_set);
//   - use_subaddr (txkey_pub = r*D) <=> num_stdaddresses == 0 && num_subaddresses == 1;
//   - need_additional_txkeys <=> num_sub > 0 && (num_std > 0 || num_sub > 1).
// ===========================================================================
static bool addr_equal(const uts_account_public_address_t *a,
                       const uts_account_public_address_t *b)
{
    return memcmp(a->spend_public_key, b->spend_public_key, 32) == 0 &&
           memcmp(a->view_public_key,  b->view_public_key,  32) == 0;
}

bool sign_dst_is_change(const uts_tx_construction_data_t *tx,
                        const uts_tx_destination_entry_t *d)
{
    // Monero: change_addr && dst_entr.addr == *change_addr && !dst_entr.is_subaddress
    if (d->is_subaddress) return false;
    return addr_equal(&d->addr, &tx->change_dts.addr);
}

bool sign_classify_dsts(const uts_tx_construction_data_t *tx,
                        bool *use_subaddr_out,
                        uint8_t single_sub_spend_pub[32],
                        bool *need_additional_out)
{
    uint32_t n_std = 0, n_sub = 0;
    uts_account_public_address_t uniq[UTS_MAX_DESTS];
    uint32_t n_uniq = 0;
    const uts_tx_destination_entry_t *single_sub = NULL;

    for (uint32_t i = 0; i < tx->n_splitted_dsts; i++) {
        const uts_tx_destination_entry_t *d = &tx->splitted_dsts[i];

        // адрес сдачи исключаем (сравнение по полному адресу, как в Monero)
        if (addr_equal(&d->addr, &tx->change_dts.addr)) continue;

        bool dup = false;
        for (uint32_t k = 0; k < n_uniq; k++) {
            if (addr_equal(&uniq[k], &d->addr)) { dup = true; break; }
        }
        if (dup) continue;
        if (n_uniq < UTS_MAX_DESTS) uniq[n_uniq++] = d->addr;

        if (d->is_subaddress) { n_sub++; single_sub = d; }
        else                  { n_std++; }
    }

    bool use_subaddr = (n_std == 0 && n_sub == 1);
    bool need_additional = (n_sub > 0) && (n_std > 0 || n_sub > 1);

    logf_("classify: n_std=%u n_sub=%u -> use_subaddr=%d need_additional=%d",
          (unsigned)n_std, (unsigned)n_sub, (int)use_subaddr, (int)need_additional);

    if (use_subaddr_out) *use_subaddr_out = use_subaddr;
    if (need_additional_out) *need_additional_out = need_additional;
    if (single_sub_spend_pub) {
        if (use_subaddr && single_sub)
            memcpy(single_sub_spend_pub, single_sub->addr.spend_public_key, 32);
        else
            memset(single_sub_spend_pub, 0, 32);
    }
    return true;
}

// ===========================================================================
// Хранилище x и ki для каждого источника
// ===========================================================================
static uint8_t g_src_x[UTS_MAX_SOURCES][32];
static uint8_t g_src_ki[UTS_MAX_SOURCES][32];
static bool    g_src_x_valid[UTS_MAX_SOURCES];

// ---------------------------------------------------------------------------
// Per-output derivations, вычисленные в sign_build_prefix.
// rct-часть обязана использовать ИМЕННО их, иначе ключ выхода и
// маска/ecdhInfo будут посчитаны от разных derivation.
// ---------------------------------------------------------------------------
static uint8_t g_out_deriv[UTS_MAX_DESTS][32];
static uint32_t g_out_deriv_n = 0;

bool sign_get_output_derivation(uint32_t i, uint8_t deriv_out[32]) {
    if (i >= g_out_deriv_n) return false;
    memcpy(deriv_out, g_out_deriv[i], 32);
    return true;
}

uint32_t sign_get_n_output_derivations(void) { return g_out_deriv_n; }

bool sign_get_source_x(uint32_t s, uint8_t x_out[32]) {
    if (s >= UTS_MAX_SOURCES || !g_src_x_valid[s]) return false;
    memcpy(x_out, g_src_x[s], 32);
    return true;
}

bool sign_get_source_ki(uint32_t s, uint8_t ki_out[32]) {
    if (s >= UTS_MAX_SOURCES || !g_src_x_valid[s]) return false;
    memcpy(ki_out, g_src_ki[s], 32);
    return true;
}

// ===========================================================================
// Хранилище ОТСОРТИРОВАННЫХ источников — в PSRAM
// ===========================================================================
static uts_tx_source_entry_t *g_sorted_sources = NULL;
static uint32_t               g_sorted_n_sources = 0;

static bool ensure_sorted_sources_alloc(void) {
    if (g_sorted_sources) return true;
    g_sorted_sources = (uts_tx_source_entry_t *)psram_alloc(
        sizeof(uts_tx_source_entry_t) * UTS_MAX_SOURCES);
    if (!g_sorted_sources) {
        platform_log("sign_tx_construct: psram_alloc sorted_sources FAILED");
        return false;
    }
    return true;
}

bool sign_get_sorted_source(uint32_t s, uts_tx_source_entry_t *out) {
    if (!g_sorted_sources) return false;
    if (s >= g_sorted_n_sources) return false;
    memcpy(out, &g_sorted_sources[s], sizeof(*out));
    return true;
}

uint32_t sign_get_n_sources(void) {
    return g_sorted_n_sources;
}

void sign_set_raw_plain(const uint8_t *raw, size_t len) {
    g_raw_plain = raw;
    g_raw_plain_len = len;
}

static void logf_(const char *fmt, ...) {
    char buf[200];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    platform_log(buf);
}

static void log_hex32(const char *prefix, const uint8_t *p) {
    // 160 байт и жёсткая проверка границы: длинный префикс раньше уводил
    // snprintf за конец буфера (n мог стать больше sizeof(buf)).
    char buf[160];
    int n = snprintf(buf, sizeof(buf), "%s=", prefix);
    if (n < 0 || n >= (int)sizeof(buf)) { platform_log(prefix); return; }
    for (int i = 0; i < 32 && n < (int)sizeof(buf) - 1; i++)
        n += snprintf(buf + n, sizeof(buf) - n, "%02x", p[i]);
    platform_log(buf);
}

static size_t put_varint(uint8_t *out, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)(v & 0x7f) | 0x80;
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

// ===========================================================================
// Base58 (Monero-style) decode
// ===========================================================================




// ===========================================================================
// Хеши idx
// ===========================================================================
static void deriv_to_scalar_varint(const uint8_t deriv[32], uint64_t idx,
                                   uint8_t scalar_out[32]) {
    uint8_t hbuf[32 + 10];
    memcpy(hbuf, deriv, 32);
    size_t vlen = 0;
    uint64_t v = idx;
    while (v >= 0x80) { hbuf[32 + vlen++] = (uint8_t)(v & 0x7f) | 0x80; v >>= 7; }
    hbuf[32 + vlen++] = (uint8_t)v;
    cn_fast_hash(hbuf, 32 + vlen, (char*)scalar_out);
    sc_reduce32(scalar_out);
}

static bool derive_subaddr_B(uint32_t major, uint32_t minor, uint8_t D_out[32]) {
    uint8_t m[32];
    crypto_generate_subaddress_secret_key(g_view_secret_key, major, minor, m);
    ge_p3 mG_p3;
    ge_scalarmult_base(&mG_p3, m);
    ge_p3 B_p3;
    if (ge_frombytes_vartime(&B_p3, g_spend_public_key) != 0) return false;
    ge_cached B_cached;
    ge_p3_to_cached(&B_cached, &B_p3);
    ge_p1p1 sum_p1p1;
    ge_add(&sum_p1p1, &mG_p3, &B_cached);
    ge_p3 D_p3;
    ge_p1p1_to_p3(&D_p3, &sum_p1p1);
    ge_p3_tobytes(D_out, &D_p3);
    return true;
}

// ===========================================================================
// === ИСПРАВЛЕНО: одноразовый ключ входа выводится без захардкоженного адреса ===
// ===========================================================================
//
// Было: адрес кошелька лежал строкой в коде (WALLET_ADDR), из него брался D,
// и дальше по кольцу искался выход, для которого сходится P = Hs(d||i)·G + D.
// Это второй источник правды рядом с secrets.h, и тратить можно было только
// выходы, пришедшие на этот один адрес.
//
// Стало — как в Monero (is_out_to_acc_precomp -> derive_subaddress_public_key):
// D ВЫЧИТАЕТСЯ, а не угадывается:
//
//     D = P − Hs(d ‖ varint(i))·G
//
// Если D == B — выход пришёл на основной адрес. Иначе это субадрес, и остаётся
// найти пару (major, minor), для которой B + m(major,minor)·G == D. Подсказки
// берём из unsigned set (subaddr_account / subaddr_indices), но каждая проверяется
// этим равенством, так что соврать подсказкой нельзя.
//
// Кандидатов на derivation два, в порядке Monero: сначала общий 8·a·R, затем
// 8·a·R_add[i] — без второго не тратятся выходы, пришедшие на субадрес в составе
// транзакции с несколькими получателями.
//
// x проверяется обязательным равенством x·G == P (in_ephemeral.pub == out_key
// в Monero). Без него ошибка вылезла бы только на стороне сети.

typedef struct {
    uint8_t  x[32];
    uint8_t  ki[32];
    uint32_t major, minor;
    bool     is_subaddr;
} src_keys_t;

// D_cand = B + m(major,minor)·G ; сравнение с восстановленным D
static bool subaddr_matches(uint32_t major, uint32_t minor, const uint8_t D[32]) {
    uint8_t D_cand[32];
    if (!derive_subaddr_B(major, minor, D_cand)) return false;
    return memcmp(D_cand, D, 32) == 0;
}

// Подсказки из unsigned set, затем ограниченный перебор.
static bool resolve_subaddr_index(const uts_tx_construction_data_t *tx,
                                  const uint8_t D[32],
                                  uint32_t *out_major, uint32_t *out_minor)
{
    const uint32_t maj = tx->subaddr_account;

    for (uint32_t k = 0; k < tx->n_subaddr_indices; k++) {
        if (subaddr_matches(maj, tx->subaddr_indices[k], D)) {
            *out_major = maj; *out_minor = tx->subaddr_indices[k];
            return true;
        }
    }
    // Базовый адрес аккаунта: при major != 0 это настоящий субадрес, и в
    // subaddr_indices он попадать не обязан.
    if (subaddr_matches(maj, 0, D)) { *out_major = maj; *out_minor = 0; return true; }

    // Запасной ограниченный перебор. Monero держит таблицу
    // (major+50) x (minor+200) в памяти; здесь считаем на месте, поэтому уже.
    for (uint32_t a = 0; a <= 5; a++) {
        for (uint32_t b = 0; b <= 500; b++) {
            if (subaddr_matches(a, b, D)) { *out_major = a; *out_minor = b; return true; }
            if ((b & 0x3F) == 0) vTaskDelay(1);
        }
    }
    return false;
}

// Одна попытка с конкретной derivation.
static bool try_derivation(const uts_tx_construction_data_t *tx,
                           const uint8_t deriv[32], uint64_t idx,
                           const uint8_t P[32], src_keys_t *out)
{
    uint8_t hs[32];
    deriv_to_scalar_varint(deriv, idx, hs);   // Monero кодирует индекс только varint'ом

    // D = P − hs·G
    ge_p3 P_p3;
    if (ge_frombytes_vartime(&P_p3, P) != 0) return false;
    ge_p3 hsG_p3;
    ge_scalarmult_base(&hsG_p3, hs);
    ge_cached hsG_cached;
    ge_p3_to_cached(&hsG_cached, &hsG_p3);
    ge_p1p1 diff_p1p1;
    ge_sub(&diff_p1p1, &P_p3, &hsG_cached);
    ge_p3 D_p3;
    ge_p1p1_to_p3(&D_p3, &diff_p1p1);
    uint8_t D[32];
    ge_p3_tobytes(D, &D_p3);

    uint8_t x[32];
    if (memcmp(D, g_spend_public_key, 32) == 0) {
        out->is_subaddr = false;
        out->major = out->minor = 0;
        sc_add(x, hs, g_spend_secret_key);
    } else {
        uint32_t maj, mino;
        if (!resolve_subaddr_index(tx, D, &maj, &mino)) {
            log_hex32("субадрес не опознан, D", D);
            return false;
        }
        out->is_subaddr = true;
        out->major = maj; out->minor = mino;
        uint8_t m_sub[32], b_plus_m[32];
        crypto_generate_subaddress_secret_key(g_view_secret_key, maj, mino, m_sub);
        sc_add(b_plus_m, g_spend_secret_key, m_sub);
        sc_add(x, hs, b_plus_m);
        memset(m_sub, 0, sizeof(m_sub));
        memset(b_plus_m, 0, sizeof(b_plus_m));
    }

    // Обязательная проверка: x·G == P
    {
        ge_p3 xG_p3;
        uint8_t xG[32];
        ge_scalarmult_base(&xG_p3, x);
        ge_p3_tobytes(xG, &xG_p3);
        if (memcmp(xG, P, 32) != 0) {
            memset(x, 0, sizeof(x));
            return false;
        }
    }

    // key image = x · Hp(P)
    uint8_t hp_hash[32];
    cn_fast_hash(P, 32, (char *)hp_hash);
    ge_p2 hp_p2;
    ge_fromfe_frombytes_vartime(&hp_p2, hp_hash);
    ge_p1p1 hp_p1p1;
    ge_mul8(&hp_p1p1, &hp_p2);
    ge_p3 hp_p3;
    ge_p1p1_to_p3(&hp_p3, &hp_p1p1);
    ge_p2 ki_p2;
    ge_scalarmult(&ki_p2, x, &hp_p3);
    ge_tobytes(out->ki, &ki_p2);

    memcpy(out->x, x, 32);
    memset(x, 0, sizeof(x));
    memset(hs, 0, sizeof(hs));
    return true;
}

static bool resolve_source_keys(const uts_tx_construction_data_t *tx,
                                const uts_tx_source_entry_t *src,
                                uint32_t s_idx, src_keys_t *out)
{
    memset(out, 0, sizeof(*out));

    if (src->real_output >= src->n_outputs) {
        logf_("src[%u]: real_output=%llu вне кольца (%u)", s_idx,
              (unsigned long long)src->real_output, src->n_outputs);
        return false;
    }
    const uint8_t *P = src->outputs[src->real_output].ctkey.dest;
    const uint64_t idx = src->real_output_in_tx_index;

    // Кандидат 1: общий ключ транзакции
    uint8_t deriv[32];
    if (crypto_generate_key_derivation(src->real_out_tx_key, g_view_secret_key, deriv)) {
        if (try_derivation(tx, deriv, idx, P, out)) {
            logf_("src[%u]: ключ найден по общему R%s", s_idx,
                  out->is_subaddr ? " (субадрес)" : "");
            return true;
        }
    }

    // Кандидат 2: additional_tx_keys[real_output_in_tx_index]
    if (src->n_additional_tx_keys > 0) {
        if (idx >= src->n_additional_tx_keys) {
            logf_("src[%u]: idx_in_tx=%llu >= additional_tx_keys=%u", s_idx,
                  (unsigned long long)idx, src->n_additional_tx_keys);
            return false;
        }
        if (crypto_generate_key_derivation(src->additional_tx_keys[idx],
                                           g_view_secret_key, deriv)) {
            if (try_derivation(tx, deriv, idx, P, out)) {
                logf_("src[%u]: ключ найден по additional R[%llu]%s", s_idx,
                      (unsigned long long)idx, out->is_subaddr ? " (субадрес)" : "");
                return true;
            }
        }
    }

    logf_("src[%u]: не удалось вывести одноразовый ключ — отказ", s_idx);
    return false;
}

static bool build_key_offsets(const uts_tx_source_entry_t *src, uint64_t *rel) {
    uint64_t prev = 0;
    for (uint32_t i = 0; i < src->n_outputs; i++) {
        uint64_t a = src->outputs[i].global_index;
        if (i == 0) rel[i] = a;
        else {
            if (a < prev) return false;
            rel[i] = a - prev;
        }
        prev = a;
    }
    return true;
}

// ===========================================================================
// === ИСПРАВЛЕНО: tx_extra собирается по TLV, payment id шифруется ===
// ===========================================================================
//
// Порядок полей задаёт sort_tx_extra() в Monero:
//   0x01 tx_pub_key -> 0x04 additional_pub_keys -> 0x02 nonce -> 0x03 -> 0xDE -> 0x00
// (раньше 0x04 дописывался в самый конец, после nonce — расходилось с эталоном).
//
// Payment id в unsigned_tx_set лежит В ОТКРЫТОМ ВИДЕ: wallet2 расшифровывает его
// перед экспортом (get_construction_data_with_decrypted_short_payment_id), потому
// что подписывающая сторона генерирует новый tx_key. Значит эти 8 байт надо
// ЗАXORить, а не подменять: иначе платёж на интегрированный адрес уходит без
// payment id и не зачисляется получателем.
//
// Ключ шифрования — всегда основной tx_key (не additional): в Monero блок
// payment id выполняется ДО classify_addresses, когда additional-ключей ещё нет.

#define TX_EXTRA_TAG_PADDING          0x00
#define TX_EXTRA_TAG_PUBKEY           0x01
#define TX_EXTRA_NONCE                0x02
#define TX_EXTRA_MERGE_MINING         0x03
#define TX_EXTRA_ADDITIONAL_PUB       0x04
#define TX_EXTRA_MINERGATE            0xDE
#define TX_EXTRA_NONCE_ENC_PID        0x01
#define TX_EXTRA_NONCE_PID            0x00
#define HASH_KEY_ENCRYPTED_PAYMENT_ID 0x8d
#define EXTRA_MAX_FIELDS              16

typedef struct { uint8_t tag; const uint8_t *data; size_t len; } extra_field_t;

static size_t read_varint(const uint8_t *p, size_t avail, uint64_t *out) {
    uint64_t v = 0; int sh = 0; size_t i = 0;
    while (i < avail) {
        uint8_t c = p[i++];
        v |= (uint64_t)(c & 0x7f) << sh;
        if (!(c & 0x80)) { *out = v; return i; }
        sh += 7;
        if (sh > 63) return 0;
    }
    return 0;
}

// Разбор extra в список полей. Неизвестный тег — отказ: в Monero неразбираемый
// extra роняет sort_tx_extra(), а значит и всю сборку транзакции.
static bool parse_extra_tlv(const uint8_t *e, size_t n,
                            extra_field_t *f, uint32_t *nf)
{
    size_t pos = 0;
    *nf = 0;
    while (pos < n) {
        if (*nf >= EXTRA_MAX_FIELDS) return false;
        uint8_t tag = e[pos];
        size_t start = pos++;
        if (tag == TX_EXTRA_TAG_PADDING) {
            while (pos < n) { if (e[pos] != 0) return false; pos++; }
        } else if (tag == TX_EXTRA_TAG_PUBKEY) {
            if (pos + 32 > n) return false;
            pos += 32;
        } else if (tag == TX_EXTRA_NONCE || tag == TX_EXTRA_MERGE_MINING ||
                   tag == TX_EXTRA_MINERGATE) {
            uint64_t l; size_t k = read_varint(e + pos, n - pos, &l);
            if (!k || pos + k + l > n) return false;
            pos += k + (size_t)l;
        } else if (tag == TX_EXTRA_ADDITIONAL_PUB) {
            uint64_t c; size_t k = read_varint(e + pos, n - pos, &c);
            if (!k || c > UTS_MAX_DESTS || pos + k + c * 32 > n) return false;
            pos += k + (size_t)c * 32;
        } else {
            logf_("extra: неизвестный тег 0x%02x", (unsigned)tag);
            return false;
        }
        f[*nf].tag = tag;
        f[*nf].data = e + start;
        f[*nf].len = pos - start;
        (*nf)++;
    }
    return true;
}

// Порт cryptonote::get_destination_view_key_pub().
// Пропускает нулевые суммы, адрес сдачи и повторы. Если непогашенных получателей
// больше одного — в Monero возвращается null_pkey, и это ошибка, а не «возьмём
// первого попавшегося». false здесь == null_pkey.
static bool get_destination_view_key_pub(const uts_tx_construction_data_t *tx,
                                         uint8_t out[32])
{
    uts_account_public_address_t addr;
    memset(&addr, 0, sizeof(addr));
    uint32_t count = 0;

    for (uint32_t i = 0; i < tx->n_splitted_dsts; i++) {
        const uts_tx_destination_entry_t *d = &tx->splitted_dsts[i];
        if (d->amount == 0) continue;
        if (addr_equal(&d->addr, &tx->change_dts.addr)) continue;
        if (addr_equal(&d->addr, &addr)) continue;
        if (count > 0) return false;            // null_pkey
        addr = d->addr;
        count++;
    }

    if (count == 0) memcpy(out, tx->change_dts.addr.view_public_key, 32);
    else            memcpy(out, addr.view_public_key, 32);

    for (int i = 0; i < 32; i++) if (out[i]) return true;
    return false;                               // всё нули == null_pkey
}

// Порт device_default::encrypt_payment_id(). Шифрование и расшифровка — одна и
// та же операция (XOR). Общий секрет — generate_key_derivation, то есть 8*r*A,
// с умножением на 8; без него получатель ничего не расшифрует.
static bool xor_payment_id8(uint8_t pid8[8], const uint8_t view_pub[32],
                            const uint8_t tx_sec[32])
{
    uint8_t deriv[32];
    if (!crypto_generate_key_derivation(view_pub, tx_sec, deriv)) {
        logf_("payment_id: view_pub не на кривой");
        return false;
    }
    uint8_t buf[33];
    memcpy(buf, deriv, 32);
    buf[32] = HASH_KEY_ENCRYPTED_PAYMENT_ID;
    uint8_t h[32];
    cn_fast_hash(buf, sizeof(buf), (char *)h);
    for (int i = 0; i < 8; i++) pid8[i] ^= h[i];
    memset(deriv, 0, sizeof(deriv));
    memset(buf, 0, sizeof(buf));
    memset(h, 0, sizeof(h));
    return true;
}

static size_t build_extra_from_uts(const uts_tx_construction_data_t *tx,
                                   const uint8_t tx_secret_key[32],
                                   const uint8_t R_pub[32],
                                   const uint8_t (*add_pub)[32], uint32_t n_add_pub,
                                   uint8_t *out_extra, size_t out_cap)
{
    extra_field_t f[EXTRA_MAX_FIELDS];
    uint32_t nf = 0;
    if (tx->extra_len > 0 && !parse_extra_tlv(tx->extra, tx->extra_len, f, &nf)) {
        logf_("extra: не разбирается как TLV — отказываемся подписывать");
        return 0;
    }

    // ---- payment id ----
    uint8_t nonce_out[11];
    size_t  nonce_out_len = 0;      // готовое поле 0x02, которое мы сами соберём
    bool    keep_original_nonce = false;   // длинный pid: переносим как есть
    bool    add_dummy = true;

    const extra_field_t *nonce = NULL;
    for (uint32_t i = 0; i < nf; i++)
        if (f[i].tag == TX_EXTRA_NONCE) { nonce = &f[i]; break; }

    if (nonce) {
        uint64_t len;
        size_t k = read_varint(nonce->data + 1, nonce->len - 1, &len);
        const uint8_t *payload = nonce->data + 1 + k;
        if (k && len == 9 && payload[0] == TX_EXTRA_NONCE_ENC_PID) {
            uint8_t pid8[8];
            memcpy(pid8, payload + 1, 8);
            uint8_t view_pub[32];
            if (!get_destination_view_key_pub(tx, view_pub)) {
                logf_("extra: есть payment id, но получателей не ровно один — "
                      "зашифровать нечем, отказ");
                return 0;                       // как LOG_ERROR + return false
            }
            if (!xor_payment_id8(pid8, view_pub, tx_secret_key)) return 0;
            nonce_out[0] = TX_EXTRA_NONCE;
            nonce_out[1] = 9;
            nonce_out[2] = TX_EXTRA_NONCE_ENC_PID;
            memcpy(nonce_out + 3, pid8, 8);
            nonce_out_len = 11;
            add_dummy = false;
            logf_("extra: payment id зашифрован");
        } else if (k && len == 33 && payload[0] == TX_EXTRA_NONCE_PID) {
            keep_original_nonce = true;         // длинный pid не трогаем
            add_dummy = false;
            logf_("extra: длинный payment id перенесён без изменений");
        }
    }

    // Monero не добавляет dummy, если получателей больше, чем «один плюс сдача».
    if (tx->n_splitted_dsts > 2) add_dummy = false;

    if (add_dummy) {
        uint8_t pid8[8];
        memset(pid8, 0, 8);
        uint8_t view_pub[32];
        if (get_destination_view_key_pub(tx, view_pub) &&
            xor_payment_id8(pid8, view_pub, tx_secret_key)) {
            nonce_out[0] = TX_EXTRA_NONCE;
            nonce_out[1] = 9;
            nonce_out[2] = TX_EXTRA_NONCE_ENC_PID;
            memcpy(nonce_out + 3, pid8, 8);
            nonce_out_len = 11;
            logf_("extra: добавлен dummy payment id");
        } else {
            // В Monero это только LOG_ERROR, сборка продолжается.
            logf_("extra: нет ключа для dummy payment id — поле не добавлено");
        }
    }

    // ---- сборка в каноническом порядке ----
    size_t pos = 0;
    #define EX_EMIT(p, n) do { if (pos + (n) > out_cap) { \
            logf_("extra: не влезает в буфер"); return 0; } \
            memcpy(out_extra + pos, (p), (n)); pos += (n); } while (0)

    // 0x01 — свежий tx_pub_key вместо того, что был в unsigned set
    { uint8_t tag = TX_EXTRA_TAG_PUBKEY; EX_EMIT(&tag, 1); EX_EMIT(R_pub, 32); }

    // 0x04 — additional_tx_pub_keys, ДО nonce
    if (n_add_pub > 0) {
        uint8_t tag = TX_EXTRA_ADDITIONAL_PUB, vbuf[10];
        size_t vlen = put_varint(vbuf, n_add_pub);
        EX_EMIT(&tag, 1); EX_EMIT(vbuf, vlen);
        for (uint32_t i = 0; i < n_add_pub; i++) EX_EMIT(add_pub[i], 32);
    }

    // 0x02 — nonce
    if (nonce_out_len) {
        EX_EMIT(nonce_out, nonce_out_len);
    } else if (keep_original_nonce) {
        for (uint32_t i = 0; i < nf; i++)
            if (f[i].tag == TX_EXTRA_NONCE) EX_EMIT(f[i].data, f[i].len);
    }

    // 0x03, 0xDE, 0x00 — переносим как есть, в исходном порядке
    static const uint8_t tail_tags[3] = { TX_EXTRA_MERGE_MINING,
                                          TX_EXTRA_MINERGATE,
                                          TX_EXTRA_TAG_PADDING };
    for (int t = 0; t < 3; t++)
        for (uint32_t i = 0; i < nf; i++)
            if (f[i].tag == tail_tags[t]) EX_EMIT(f[i].data, f[i].len);

    #undef EX_EMIT

    if (pos > 1060) {   // MAX_TX_EXTRA_SIZE — политика ретрансляции monerod
        logf_("extra: %u байт > MAX_TX_EXTRA_SIZE", (unsigned)pos);
        return 0;
    }
    return pos;
}
// ===========================================================================
// Точка входа
// ===========================================================================
size_t sign_build_prefix(const unsigned_tx_set_t *uts,
                         const uint8_t tx_secret_key[32],
                         const uint8_t *additional_tx_keys,
                         uint32_t n_additional_tx_keys,
                         uint8_t *out_buf, size_t out_cap,
                         uint8_t prefix_hash_out[32])
{
    platform_log("sbp: ENTER");

    (void)additional_tx_keys;
    (void)n_additional_tx_keys;

    if (!uts) { platform_log("sbp: uts == NULL"); return 0; }
    if (uts->n_txes != 1) {
        platform_log("sbp: n_txes != 1");
        return 0;
    }

    memset(g_src_x_valid, 0, sizeof(g_src_x_valid));
    g_sorted_n_sources = 0;

    // ---- 0. Проверка view_pub ----
    {
        uint8_t view_pub_check[32];
        crypto_secret_key_to_public_key(g_view_secret_key, view_pub_check);
        log_hex32("view_pub_check", view_pub_check);
        log_hex32("view_pub_in_uts",
                  uts->txes[0].change_dts.addr.view_public_key);
        if (memcmp(view_pub_check, uts->txes[0].change_dts.addr.view_public_key, 32) != 0) {
            logf_("WARNING: view_pub_check MISMATCH — check secrets.h");
        } else {
            logf_("view_pub_check OK");
        }
    }

    // Адрес кошелька больше ниоткуда не берётся: (major, minor) выводится
    // отдельно для каждого входа в resolve_source_keys(). Разные входы одной
    // транзакции законно живут на разных minor — поэтому глобального
    // (is_subaddress, maj, mino) здесь быть не должно.

    // ---- 2b. Рабочая копия tx в PSRAM ----
    static uts_tx_construction_data_t *tx_psram = NULL;
    if (!tx_psram) {
        logf_("sign_build_prefix: psram_alloc tx (size=%u)",
              (unsigned)sizeof(uts_tx_construction_data_t));
        tx_psram = (uts_tx_construction_data_t *)psram_alloc(
            sizeof(uts_tx_construction_data_t));
        if (!tx_psram) {
            logf_("sign_build_prefix: psram_alloc tx FAILED");
            return 0;
        }
    }
    memcpy(tx_psram, &uts->txes[0], sizeof(*tx_psram));
    uts_tx_construction_data_t *tx = tx_psram;


    // real_output и real_output_in_tx_index берём из unsigned set как есть
    // (так же делает Monero) и проверяем равенством x·G == P в
    // resolve_source_keys() — переискивать их по кольцу не нужно и опасно:
    // подставной член кольца может совпасть и увести подпись на чужой выход.

    // ---- 4. Сортировка колец ----
    for (uint32_t s = 0; s < tx->n_sources; s++) {
        uts_tx_source_entry_t *src = &tx->sources[s];
        uint8_t real_dest[32];
        memcpy(real_dest, src->outputs[src->real_output].ctkey.dest, 32);

        for (uint32_t a = 0; a < src->n_outputs; a++) {
            for (uint32_t b = a + 1; b < src->n_outputs; b++) {
                if (src->outputs[b].global_index < src->outputs[a].global_index) {
                    uts_tx_source_output_t t = src->outputs[a];
                    src->outputs[a] = src->outputs[b];
                    src->outputs[b] = t;
                }
            }
        }
        for (uint32_t i = 0; i < src->n_outputs; i++) {
            if (memcmp(src->outputs[i].ctkey.dest, real_dest, 32) == 0) {
                src->real_output = i; break;
            }
        }
        logf_("src[%u]: after sort real_output=%u", s, src->real_output);
        vTaskDelay(1);
    }

    // =======================================================================
    // === ДОБАВЛЕНО: пасс A — key images, затем сортировка входов ===
    //
    // Консенсус с HF7 (Blockchain::check_tx_inputs): key images во входах должны
    // строго УБЫВАТЬ при побайтовом сравнении, иначе "transaction has unsorted
    // inputs". Monero сортирует в construct_tx_with_tx_key и переставляет вместе
    // с vin ещё in_contexts (одноразовые секретные ключи) и sources.
    //
    // wallet2 кладёт в unsigned set sources в порядке ВЫБОРА, не отсортированные
    // (construction_data.sources = sources_copy, снимок до сортировки), так что
    // сортировать обязаны мы. С двумя входами шанс угадать порядок 1/2, с тремя
    // 1/6 — то есть без этого почти любая транзакция с несколькими входами
    // отвергается демоном ещё до проверки подписей.
    //
    // Сортируем ДО сборки prefix: тогда всё, что считается дальше (pseudoOuts,
    // CLSAG, mixRing, prefix_hash), автоматически встаёт в тот же порядок, что и
    // vin, и отдельная перестановка не нужна.
    // =======================================================================
    for (uint32_t i = 0; i < tx->n_sources; i++) {
        src_keys_t sk;
        if (!resolve_source_keys(tx, &tx->sources[i], i, &sk)) return 0;
        // Monero гарантирует, что все входы одной транзакции принадлежат одному
        // аккаунту: расхождение означает несогласованный unsigned set.
        if (sk.is_subaddr && sk.major != tx->subaddr_account) {
            logf_("src[%u]: major=%u, а в unsigned set subaddr_account=%u",
                  i, sk.major, tx->subaddr_account);
            return 0;
        }
        memcpy(g_src_x[i], sk.x, 32);
        memcpy(g_src_ki[i], sk.ki, 32);
        g_src_x_valid[i] = true;
        memset(&sk, 0, sizeof(sk));
    }

    // Сортировка вставками по убыванию key image. n <= 8, так что простого
    // алгоритма достаточно; вместе с источником переставляем ВСЁ, что к нему
    // привязано по индексу: x, ki, R и флаг кодировки индекса.
    {
        static uts_tx_source_entry_t tmp_src;   // 3 КБ — не на стек
        for (uint32_t i = 1; i < tx->n_sources; i++) {
            for (uint32_t j = i; j > 0; j--) {
                if (memcmp(g_src_ki[j - 1], g_src_ki[j], 32) >= 0) break;
                uint32_t a = j - 1, b = j;
                tmp_src = tx->sources[a];
                tx->sources[a] = tx->sources[b];
                tx->sources[b] = tmp_src;
                uint8_t t32[32];
                memcpy(t32, g_src_ki[a], 32); memcpy(g_src_ki[a], g_src_ki[b], 32); memcpy(g_src_ki[b], t32, 32);
                memcpy(t32, g_src_x[a],  32); memcpy(g_src_x[a],  g_src_x[b],  32); memcpy(g_src_x[b],  t32, 32);
            }
        }
        memset(&tmp_src, 0, sizeof(tmp_src));
    }

    // Одинаковые key images демон отвергает отдельной проверкой
    // (check_tx_inputs_keyimages_diff) — лучше упасть здесь.
    for (uint32_t i = 1; i < tx->n_sources; i++) {
        if (memcmp(g_src_ki[i - 1], g_src_ki[i], 32) <= 0) {
            logf_("sign_build_prefix: key images не строго убывают на входе %u", i);
            return 0;
        }
    }
    if (tx->n_sources > 1)
        logf_("sign_build_prefix: входы отсортированы по key image (%u шт.)",
              (unsigned)tx->n_sources);

    // ---- 4b. Сохраняем отсортированные источники в PSRAM ----
    if (!ensure_sorted_sources_alloc()) {
        logf_("sign_build_prefix: ensure_sorted_sources_alloc FAILED");
        return 0;
    }
    g_sorted_n_sources = tx->n_sources;
    memcpy(g_sorted_sources, tx->sources,
           sizeof(uts_tx_source_entry_t) * tx->n_sources);
    logf_("sign_build_prefix: saved %u sorted sources", g_sorted_n_sources);

    // ---- 5. Сборка prefix ----
    size_t pos = 0;
    uint8_t tmp[16];
    uint8_t zero = 0x00;
    size_t n;

    #define EMIT(ptr, len) do { \
        if (pos + (len) > out_cap) return 0; \
        memcpy(out_buf + pos, (ptr), (len)); \
        pos += (len); \
    } while(0)

    uint8_t ver = 2;
    EMIT(&ver, 1);
    n = put_varint(tmp, tx->unlock_time);
    EMIT(tmp, n);
    n = put_varint(tmp, tx->n_sources);
    EMIT(tmp, n);

    for (uint32_t i = 0; i < tx->n_sources; i++) {
        const uts_tx_source_entry_t *src = &tx->sources[i];
        uint8_t tag = 0x02;
        EMIT(&tag, 1);
        EMIT(&zero, 1);

        n = put_varint(tmp, src->n_outputs);
        EMIT(tmp, n);

        uint64_t rel[UTS_MAX_RING_SIZE];
        if (!build_key_offsets(src, rel)) return 0;
        for (uint32_t k = 0; k < src->n_outputs; k++) {
            n = put_varint(tmp, rel[k]);
            EMIT(tmp, n);
        }

        // key image уже посчитан в пассе A и стоит в отсортированном порядке
        const uint8_t *ki = g_src_ki[i];
        EMIT(ki, 32);

        char kb[68];
        for (int b = 0; b < 32; b++) sprintf(kb + b*2, "%02x", ki[b]);
        kb[64] = 0;
        logf_("src[%u] key_image=%s", i, kb);
    }

    // ---- outputs ----
    n = put_varint(tmp, tx->n_splitted_dsts);
    EMIT(tmp, n);

    // === ИСПРАВЛЕНО: classify_addresses (адрес сдачи не считается) ===
    bool single_sub_use_D = false, need_additional = false;
    uint8_t single_sub_D[32];
    sign_classify_dsts(tx, &single_sub_use_D, single_sub_D, &need_additional);

    // === ДОБАВЛЕНО: additional_tx_keys ===
    // Monero (construct_tx_with_tx_key): если среди получателей есть субадрес и
    // при этом получателей больше одного, для КАЖДОГО выхода генерируется свой
    // секрет r_i; derivation субадресного выхода считается от r_i, а в extra
    // кладётся вектор additional_tx_pub_keys.
    if (tx->n_splitted_dsts > UTS_MAX_DESTS) {
        logf_("sign_build_prefix: слишком много выходов (%u)",
              (unsigned)tx->n_splitted_dsts);
        return 0;
    }
    static uint8_t add_sk[UTS_MAX_DESTS][32];
    static uint8_t add_pub[UTS_MAX_DESTS][32];
    if (need_additional) {
        for (uint32_t k = 0; k < tx->n_splitted_dsts; k++) {
            platform_random_bytes(add_sk[k], 32);
            sc_reduce32(add_sk[k]);
        }
        logf_("sbp: need_additional_txkeys: сгенерировано %u доп. ключей",
              (unsigned)tx->n_splitted_dsts);
    }

    uint8_t R_pub[32];
    if (single_sub_use_D) {
        ge_p3 D_p3;
        if (ge_frombytes_vartime(&D_p3, single_sub_D) != 0) return 0;
        ge_p2 R_p2;
        ge_scalarmult(&R_p2, tx_secret_key, &D_p3);
        ge_tobytes(R_pub, &R_p2);
    } else {
        ge_p3 R_p3;
        ge_scalarmult_base(&R_p3, tx_secret_key);
        ge_p3_tobytes(R_pub, &R_p3);
    }

    log_hex32("tx_pubkey R", R_pub);

    for (uint32_t i = 0; i < tx->n_splitted_dsts; i++) {
        const uts_tx_destination_entry_t *d = &tx->splitted_dsts[i];
        EMIT(&zero, 1);
        if (tx->use_view_tags) { uint8_t t = 0x03; EMIT(&t, 1); }
        else                   { uint8_t t = 0x02; EMIT(&t, 1); }

        // === ИСПРАВЛЕНО ===
        // 1) derivation = 8 * r * A  (было r*A, без ge_mul8);
        // 2) для сдачи на свой обычный адрес Monero берёт derivation = 8 * a * R;
        // 3) для субадреса при need_additional_txkeys — свой секрет r_i;
        // 4) индекс выхода кодируется varint'ом (было 8 байт LE).
        uint8_t deriv[32];
        {
            ge_p3 base_p3;
            const uint8_t *sk;
            if (sign_dst_is_change(tx, d)) {
                if (ge_frombytes_vartime(&base_p3, R_pub) != 0) return 0;
                sk = g_view_secret_key;              // derivation = 8*a*R
            } else {
                if (ge_frombytes_vartime(&base_p3, d->addr.view_public_key) != 0) return 0;
                sk = (d->is_subaddress && need_additional)
                        ? add_sk[i]                  // derivation = 8*r_i*C
                        : tx_secret_key;             // derivation = 8*r*A
            }
            ge_p2 D_p2;
            ge_scalarmult(&D_p2, sk, &base_p3);
            ge_p1p1 D_p1p1;
            ge_mul8(&D_p1p1, &D_p2);
            ge_p2 D_final;
            ge_p1p1_to_p2(&D_final, &D_p1p1);
            ge_tobytes(deriv, &D_final);
        }

        // Сохраняем derivation для rct-части (маски, ecdhInfo).
        memcpy(g_out_deriv[i], deriv, 32);

        // Доп. публичный ключ выхода: r_i*D для субадреса, r_i*G иначе.
        // Monero кладёт его для КАЖДОГО выхода, включая сдачу.
        if (need_additional) {
            if (d->is_subaddress) {
                ge_p3 D_dst_p3;
                if (ge_frombytes_vartime(&D_dst_p3, d->addr.spend_public_key) != 0) return 0;
                ge_p2 p2;
                ge_scalarmult(&p2, add_sk[i], &D_dst_p3);
                ge_tobytes(add_pub[i], &p2);
            } else {
                ge_p3 p3;
                ge_scalarmult_base(&p3, add_sk[i]);
                ge_p3_tobytes(add_pub[i], &p3);
            }
        }

        uint8_t hs[32];
        deriv_to_scalar_varint(deriv, i, hs);

        ge_p3 B_p3;
        if (ge_frombytes_vartime(&B_p3, d->addr.spend_public_key) != 0) return 0;
        ge_p3 hsG_p3;
        ge_scalarmult_base(&hsG_p3, hs);
        ge_cached B_cached;
        ge_p3_to_cached(&B_cached, &B_p3);
        ge_p1p1 sum_p1p1;
        ge_add(&sum_p1p1, &hsG_p3, &B_cached);
        ge_p3 sum_p3;
        ge_p1p1_to_p3(&sum_p3, &sum_p1p1);
        uint8_t out_eph[32];
        ge_p3_tobytes(out_eph, &sum_p3);
        EMIT(out_eph, 32);

        if (tx->use_view_tags) {
            uint8_t vbuf[48];
            size_t vp = 0;
            // === ИСПРАВЛЕНО: Monero кладёт varint(output_index), а не 8 байт LE ===
            memcpy(vbuf, "view_tag", 8); vp = 8;
            memcpy(vbuf + vp, deriv, 32); vp += 32;
            vp += put_varint(vbuf + vp, (uint64_t)i);
            uint8_t vth[32];
            cn_fast_hash(vbuf, vp, (char*)vth);
            EMIT(&vth[0], 1);
        }
    }

    g_out_deriv_n = tx->n_splitted_dsts;

    // =======================================================================
    // === ИСПРАВЛЕНО: extra с dummy encrypted_payment_id ===
    // =======================================================================
    platform_log("sbp: emit extra (from UTS + dummy pid8)");

    logf_("sbp: UTS extra_len=%u", (unsigned)tx->extra_len);
    {
        char hexbuf[140];
        int p = 0;
        size_t show = tx->extra_len < 60 ? tx->extra_len : 60;
        for (size_t k = 0; k < show; k++) {
            p += snprintf(hexbuf + p, sizeof(hexbuf) - p, "%02x", tx->extra[k]);
        }
        logf_("sbp: UTS extra[:%u]=%s", (unsigned)show, hexbuf);
    }

    {
        uint8_t extra_buf[256 + UTS_MAX_DESTS * 32];
        size_t elen = build_extra_from_uts(tx, tx_secret_key, R_pub,
                                           add_pub,
                                           need_additional ? tx->n_splitted_dsts : 0,
                                           extra_buf, sizeof(extra_buf));
        if (elen == 0) {
            logf_("sbp: build_extra_from_uts FAILED");
            return 0;
        }
        logf_("sbp: built extra len=%u", (unsigned)elen);

        // Дамп построенного extra
        {
            char hexbuf[140];
            int p = 0;
            size_t show = elen < 60 ? elen : 60;
            for (size_t k = 0; k < show; k++) {
                p += snprintf(hexbuf + p, sizeof(hexbuf) - p, "%02x", extra_buf[k]);
            }
            logf_("sbp: built extra[:%u]=%s", (unsigned)show, hexbuf);
        }

        n = put_varint(tmp, elen);
        EMIT(tmp, n);
        EMIT(extra_buf, elen);
    }

    #undef EMIT

    logf_("prefix len=%u", (unsigned)pos);
    cn_fast_hash(out_buf, pos, (char*)prefix_hash_out);

    char hb[68];
    for (int b = 0; b < 32; b++) sprintf(hb + b*2, "%02x", prefix_hash_out[b]);
    hb[64] = 0;
    logf_("prefix_hash=%s", hb);

    platform_log("sbp: DONE");
    return pos;
}