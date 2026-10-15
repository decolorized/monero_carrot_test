// outputs_parser.c
//
// Парсер outputs.bin из Monero.
//
// Формат файла (см. wallet2.cpp::export_outputs_to_str):
//   magic  "Monero output export\004" (21 байт)
//   iv     8 байт (crypto::chacha_iv)
//   ct     chacha20(plaintext)
//   sig    64 байта (Schnorr от keccak256(iv || ct))
//
// Plaintext:
//   spend_public_key : 32
//   view_public_key  : 32
//   varint(format_version)             # LEB128
//   varint(offset)                     # LEB128
//   varint(total_count)                # LEB128
//   varint(n_records)                  # LEB128
//   n_records × exported_transfer_details:
//       varint(version)                # = 1
//       pubkey[32]                     # raw
//       varint(internal_index)         # LEB128
//       varint(global_index)           # LEB128
//       tx_pubkey[32]                  # raw
//       flags[1]                       # raw
//       varint(amount)                 # LEB128
//       varint(n_additional_tx_keys)   # LEB128
//       n_additional × tx_pubkey[32]   # raw
//       varint(subaddr_major)          # LEB128
//       varint(subaddr_minor)          # LEB128
//
// ChaCha-ключ = cn_slow_hash(view_sk, 32, key, 0, 0, 0)

#include "outputs_parser.h"
#include "chacha20.h"
#include "epee_reader.h"
#include "monero_crypto.h"
#include "hash-ops.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

extern void cn_slow_hash(const void *data, size_t length, char *hash,
                         int variant, int prehashed, uint64_t height);

// ---------------------------------------------------------------------------
// Диагностика
// ---------------------------------------------------------------------------
extern void platform_log(const char *msg);

static void diag(const char *fmt, ...) {
    char buf[220];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    platform_log(buf);
}

static void hexdump_diag(const char *prefix, const uint8_t *data, size_t n) {
    char buf[220];
    size_t show = n < 32 ? n : 32;
    int off = snprintf(buf, sizeof(buf), "%s(%u)= ", prefix, (unsigned)n);
    for (size_t i = 0; i < show && off + 3 < (int)sizeof(buf); i++) {
        off += snprintf(buf + off, sizeof(buf) - off, "%02x", data[i]);
    }
    platform_log(buf);
}

static void hexdump_full(const char *prefix, const uint8_t *data, size_t n,
                         size_t max_bytes) {
    size_t shown = n < max_bytes ? n : max_bytes;
    for (size_t off = 0; off < shown; off += 32) {
        char buf[220];
        int p = snprintf(buf, sizeof(buf), "%s[%03u] ", prefix, (unsigned)off);
        size_t chunk = shown - off;
        if (chunk > 32) chunk = 32;
        for (size_t i = 0; i < chunk && p + 3 < (int)sizeof(buf); i++) {
            p += snprintf(buf + p, sizeof(buf) - p, "%02x", data[off + i]);
        }
        platform_log(buf);
    }
    if (n > max_bytes) {
        diag("%s ... truncated %u bytes", prefix, (unsigned)(n - max_bytes));
    }
}

// ---------------------------------------------------------------------------
// LEB128 varint (tools::write_varint из common/varint.h)
// ---------------------------------------------------------------------------
static bool read_varint_leb128(epee_reader *r, uint64_t *out) {
    uint64_t v = 0;
    int shift = 0;
    for (;;) {
        if (epee_at_end(r)) return false;
        uint8_t b;
        if (!epee_read_bytes(r, &b, 1)) return false;
        v |= ((uint64_t)(b & 0x7f)) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 63) return false;
    }
    *out = v;
    return true;
}

// ---------------------------------------------------------------------------
// Проверка подписи (keccak256(iv || ct))
// ---------------------------------------------------------------------------
static bool verify_keccak_sig(const uint8_t *iv, size_t iv_len,
                              const uint8_t *ct, size_t ct_len,
                              const uint8_t pubkey[32],
                              const uint8_t sig[64])
{
    size_t total = iv_len + ct_len;
    uint8_t *tmp = (uint8_t *)malloc(total);
    if (!tmp) { diag("verify_sig: OOM"); return false; }
    memcpy(tmp, iv, iv_len);
    memcpy(tmp + iv_len, ct, ct_len);

    uint8_t hash[32];
    cn_fast_hash(tmp, total, (char*)hash);
    free(tmp);

    hexdump_diag("verify_sig: hash", hash, 32);
    bool ok = crypto_check_signature(hash, pubkey, sig);
    diag("verify_sig: result=%s", ok ? "OK" : "FAIL");
    return ok;
}

// ---------------------------------------------------------------------------
// ChaCha-ключ
// ---------------------------------------------------------------------------
static void derive_chacha_key(const uint8_t view_sk[32], uint8_t key[32]) {
    cn_slow_hash(view_sk, 32, (char *)key, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// parse_outputs_bin
// ---------------------------------------------------------------------------
bool parse_outputs_bin(const uint8_t *in, size_t in_size,
                       const uint8_t view_sk[32],
                       parsed_outputs *out)
{
    memset(out, 0, sizeof(*out));

    diag("parse: in_size=%u, MAGIC_LEN=%u, IV_LEN=%u, SIG_LEN=%u",
         (unsigned)in_size, (unsigned)MAGIC_LEN,
         (unsigned)IV_LEN, (unsigned)SIG_LEN);

    if (in_size < MAGIC_LEN + IV_LEN + SIG_LEN) {
        diag("parse: input too short");
        return false;
    }
    if (memcmp(in, OUTPUT_MAGIC, MAGIC_LEN) != 0) {
        diag("parse: magic mismatch");
        return false;
    }

    const uint8_t *body = in + MAGIC_LEN;
    size_t body_len = in_size - MAGIC_LEN;

    if (body_len < IV_LEN + SIG_LEN) {
        diag("parse: body too short");
        return false;
    }

    size_t ct_len = body_len - IV_LEN - SIG_LEN;
    const uint8_t *iv  = body;
    const uint8_t *ct  = body + IV_LEN;
    const uint8_t *sig = body + IV_LEN + ct_len;

    diag("parse: ct_len=%u", (unsigned)ct_len);
    hexdump_diag("parse: iv ", iv, IV_LEN);

    // -----------------------------------------------------------------
    // 1) ChaCha-ключ = cn_slow_hash(view_sk)
    //    Единственное место, где нужна 2 МБ contiguous PSRAM.
    // -----------------------------------------------------------------
    uint8_t chacha_key[32];
    derive_chacha_key(view_sk, chacha_key);
    hexdump_diag("parse: chacha_key", chacha_key, 32);

    // -----------------------------------------------------------------
    // 2) ChaCha20-расшифровка
    // -----------------------------------------------------------------
    uint8_t *pt = (uint8_t *)malloc(ct_len ? ct_len : 1);
    if (!pt) {
        diag("parse: OOM for pt");
        memset(chacha_key, 0, sizeof(chacha_key));
        return false;
    }
    monero_chacha20(ct, ct_len, chacha_key, iv, pt);
    memset(chacha_key, 0, sizeof(chacha_key));

    hexdump_diag("parse: pt[:32] ", pt, ct_len < 32 ? ct_len : 32);

    // -----------------------------------------------------------------
    // 3) Проверка подписи
    // -----------------------------------------------------------------
    uint8_t view_pub[32];
    crypto_secret_key_to_public_key(view_sk, view_pub);

    if (!verify_keccak_sig(iv, IV_LEN, ct, ct_len, view_pub, sig)) {
        diag("parse: signature verification failed");
        memset(pt, 0, ct_len);
        free(pt);
        return false;
    }
    diag("parse: signature OK");

    hexdump_full("pt", pt, ct_len, 224);

    // -----------------------------------------------------------------
    // 4) Разбор plaintext
    // -----------------------------------------------------------------
    epee_reader r;
    epee_init(&r, pt, ct_len);

    uint8_t spend_pub[32], view_pub_stored[32];
    if (!epee_read_bytes(&r, spend_pub, 32)) {
        diag("parse: cannot read spend_pub");
        memset(pt, 0, ct_len); free(pt); return false;
    }
    if (!epee_read_bytes(&r, view_pub_stored, 32)) {
        diag("parse: cannot read view_pub_stored");
        memset(pt, 0, ct_len); free(pt); return false;
    }
    hexdump_diag("parse: spend_pub_stored", spend_pub, 32);
    hexdump_diag("parse: view_pub_stored ", view_pub_stored, 32);

    uint64_t format_version;
    if (!read_varint_leb128(&r, &format_version)) {
        diag("parse: cannot read format_version");
        memset(pt, 0, ct_len); free(pt); return false;
    }
    diag("parse: format_version=%llu", (unsigned long long)format_version);

    uint64_t offset, total_count;
    if (!read_varint_leb128(&r, &offset)) {
        diag("parse: cannot read offset");
        memset(pt, 0, ct_len); free(pt); return false;
    }
    if (!read_varint_leb128(&r, &total_count)) {
        diag("parse: cannot read total_count");
        memset(pt, 0, ct_len); free(pt); return false;
    }
    diag("parse: offset=%llu total_count=%llu",
         (unsigned long long)offset, (unsigned long long)total_count);

    uint64_t nrecords;
    if (!read_varint_leb128(&r, &nrecords)) {
        diag("parse: cannot read nrecords");
        memset(pt, 0, ct_len); free(pt); return false;
    }
    diag("parse: nrecords=%llu", (unsigned long long)nrecords);

    if (nrecords > OUTPUTS_MAX_RECORDS) {
        diag("parse: nrecords too big: %llu (max %u)",
             (unsigned long long)nrecords, (unsigned)OUTPUTS_MAX_RECORDS);
        memset(pt, 0, ct_len); free(pt); return false;
    }

    // -----------------------------------------------------------------
    // 5) Аллокация records[] в SRAM (обычный malloc).
    //    Размер = sizeof(output_record) * OUTPUTS_MAX_RECORDS ≈ 5 КБ.
    // -----------------------------------------------------------------
    size_t rec_bytes = sizeof(output_record) * OUTPUTS_MAX_RECORDS;
    diag("parse: allocating records: sizeof=%u, count=%u, total=%u bytes",
         (unsigned)sizeof(output_record),
         (unsigned)OUTPUTS_MAX_RECORDS,
         (unsigned)rec_bytes);

    out->records = (output_record *)malloc(rec_bytes);
    if (!out->records) {
        diag("parse: OOM for records (SRAM, %u bytes)", (unsigned)rec_bytes);
        memset(pt, 0, ct_len); free(pt); return false;
    }
    memset(out->records, 0, rec_bytes);
    diag("parse: records[] allocated in SRAM at %p", (void*)out->records);

    // -----------------------------------------------------------------
    // 6) Чтение записей
    // -----------------------------------------------------------------
    for (uint64_t i = 0; i < nrecords; i++) {
        uint64_t version;
        if (!read_varint_leb128(&r, &version)) {
            diag("parse: rec[%u] cannot read version", (unsigned)i);
            goto fail;
        }
        if (version != 1) {
            diag("parse: rec[%u] version=%llu (expected 1)",
                 (unsigned)i, (unsigned long long)version);
            goto fail;
        }

        output_record *rec = &out->records[i];

        if (!epee_read_bytes(&r, rec->pubkey, 32)) {
            diag("parse: rec[%u] cannot read pubkey", (unsigned)i);
            goto fail;
        }

        uint64_t v;
        if (!read_varint_leb128(&r, &v)) {
            diag("parse: rec[%u] cannot read internal_index", (unsigned)i);
            goto fail;
        }
        rec->internal_index = (uint32_t)v;

        // global_index пропускаем (не хранится в нашей структуре)
        if (!read_varint_leb128(&r, &v)) {
            diag("parse: rec[%u] cannot read global_index", (unsigned)i);
            goto fail;
        }

        if (!epee_read_bytes(&r, rec->tx_pubkey, 32)) {
            diag("parse: rec[%u] cannot read tx_pubkey", (unsigned)i);
            goto fail;
        }

        uint8_t flags;
        if (!epee_read_bytes(&r, &flags, 1)) {
            diag("parse: rec[%u] cannot read flags", (unsigned)i);
            goto fail;
        }

        // amount пропускаем
        if (!read_varint_leb128(&r, &v)) {
            diag("parse: rec[%u] cannot read amount", (unsigned)i);
            goto fail;
        }

        // ---- additional_tx_keys ----
        uint64_t nadd;
        if (!read_varint_leb128(&r, &nadd)) {
            diag("parse: rec[%u] cannot read n_additional", (unsigned)i);
            goto fail;
        }
        diag("parse: rec[%u] n_additional_tx_keys=%llu",
             (unsigned)i, (unsigned long long)nadd);

        for (uint64_t a = 0; a < nadd; a++) {
            uint8_t add_key[32];
            if (!epee_read_bytes(&r, add_key, 32)) {
                diag("parse: rec[%u] cannot read additional[%u]",
                     (unsigned)i, (unsigned)a);
                goto fail;
            }
            hexdump_diag("parse:   add_tx_key", add_key, 32);
        }

        if (!read_varint_leb128(&r, &v)) {
            diag("parse: rec[%u] cannot read subaddr_major", (unsigned)i);
            goto fail;
        }
        rec->subaddr_major = (uint32_t)v;

        if (!read_varint_leb128(&r, &v)) {
            diag("parse: rec[%u] cannot read subaddr_minor", (unsigned)i);
            goto fail;
        }
        rec->subaddr_minor = (uint32_t)v;

        diag("parse: rec[%u] ok, int_idx=%u, subaddr=%u/%u, pub=%02x%02x%02x%02x",
             (unsigned)i, (unsigned)rec->internal_index,
             (unsigned)rec->subaddr_major, (unsigned)rec->subaddr_minor,
             rec->pubkey[0], rec->pubkey[1], rec->pubkey[2], rec->pubkey[3]);
    }

    out->data = pt;
    out->data_size = ct_len;
    out->count = (size_t)nrecords;
    diag("parse: SUCCESS, %u records, format_version=%llu",
         (unsigned)nrecords, (unsigned long long)format_version);
    return true;

fail:
    if (out->records) {
        memset(out->records, 0, rec_bytes);
        free(out->records);
        out->records = NULL;
    }
    memset(pt, 0, ct_len);
    free(pt);
    return false;
}

// ---------------------------------------------------------------------------
// free_parsed_outputs
// ---------------------------------------------------------------------------
void free_parsed_outputs(parsed_outputs *p) {
    if (!p) return;

    if (p->data) {
        memset(p->data, 0, p->data_size);
        free(p->data);
        p->data = NULL;
    }
    if (p->records) {
        memset(p->records, 0, sizeof(output_record) * OUTPUTS_MAX_RECORDS);
        free(p->records);
        p->records = NULL;
    }
    p->count = 0;
    p->data_size = 0;
}