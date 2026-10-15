// rct_sig_construct.h
#ifndef RCT_SIG_CONSTRUCT_H
#define RCT_SIG_CONSTRUCT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "clsag.h"      // CLSAG_MAX_RING
#include "bp_plus.h"    // bp_plus_proof_t

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Лимиты
// ---------------------------------------------------------------------------
#define RCT_MAX_OUTPUTS  16
#define RCT_MAX_INPUTS   16
#define RCT_MAX_RING     CLSAG_MAX_RING   // = 16

// RCTTypeBulletproofPlus = 6
#define RCT_TYPE_BULLETPROOF_PLUS  6

// ---------------------------------------------------------------------------
// Базовые типы
// ---------------------------------------------------------------------------
typedef struct {
    uint8_t b[32];
} rct_key;

typedef struct {
    rct_key mask;
    rct_key dest;
} rct_out_pk;

typedef struct {
    rct_key mask;
    rct_key amount;   // только первые 8 байт значимы
} rct_ecdh_tuple;

typedef struct {
    rct_key dest;      // view public key получателя
    uint64_t amount;
    bool is_change;    // сдача на свой обычный адрес: derivation = 8*a*R, а не 8*r*A
} rct_output_t;

typedef struct {
    uint64_t amount;
    uint32_t n_ring;
    uint32_t real_output;
    struct {
        rct_key dest;
        rct_key mask;
    } ring[RCT_MAX_RING];
} rct_input_t;

typedef struct {
    uint8_t  type;
    uint64_t txn_fee;
    uint32_t n_outputs;
    uint32_t n_inputs;
    rct_ecdh_tuple ecdh_info[RCT_MAX_OUTPUTS];
    rct_out_pk     out_pk[RCT_MAX_OUTPUTS];
    rct_key        pseudo_outs[RCT_MAX_INPUTS];
} rct_sig_base_t;

typedef struct {
    rct_sig_base_t base;
    uint8_t        tx_secret_key[32];
    rct_key        tx_pub_key;
    uint8_t        out_masks[RCT_MAX_OUTPUTS][32];
    uint8_t        pseudo_outs_priv[RCT_MAX_INPUTS][32];
    clsag_t        clsags[RCT_MAX_INPUTS];
} rct_sig_ctx_t;

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------
void rct_generate_tx_key(rct_sig_ctx_t *ctx,
                         const uint8_t tx_secret_key[32],
                         bool use_subaddr,
                         const rct_key *spend_pub);

// derivations[i] — derivation i-го выхода, посчитанная при сборке prefix
// (sign_get_output_derivation). Передавать обязательно: только так ключ
// выхода и маска/ecdhInfo гарантированно считаются от одного значения.
bool rct_generate_outputs(rct_sig_ctx_t *ctx,
                          const rct_output_t *outputs,
                          uint32_t n_outputs,
                          const uint8_t (*derivations)[32]);

bool rct_generate_pseudo_outs(rct_sig_ctx_t *ctx,
                              const rct_input_t *inputs,
                              uint32_t n_inputs,
                              uint64_t fee);

size_t rct_serialize_sig_base(const rct_sig_ctx_t *ctx,
                              uint8_t *out_buf, size_t out_cap);

bool rct_get_pre_mlsag_hash(const rct_sig_ctx_t *ctx,
                            const uint8_t prefix_hash[32],
                            const uint8_t bp_hash[32],
                            uint8_t full_message_out[32]);

bool rct_check_balance(const rct_sig_ctx_t *ctx);

size_t rct_serialize_sig_prunable(const rct_sig_ctx_t *ctx,
                                  const bp_plus_proof_t *bp,
                                  uint32_t n_inputs,
                                  uint32_t n_ring,
                                  uint8_t *out_buf, size_t out_cap);

// h2 = hash(rctSigPrunable_bp_only) — без varint(nbp)
size_t rct_serialize_sig_prunable_bp_only(const bp_plus_proof_t *bp,
                                          uint8_t *out_buf, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif // RCT_SIG_CONSTRUCT_H