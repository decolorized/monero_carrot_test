// bp_plus.h
//
// Bulletproofs+ range proof для Monero.
// Порт bulletproofs_plus.cc::bulletproof_plus_PROVE на C.

#ifndef BP_PLUS_H
#define BP_PLUS_H

#include <stdint.h>
#include <stdbool.h>

// Лимиты (из cryptonote_config.h)
#define BP_PLUS_MAX_OUTPUTS  16   // BULLETPROOF_PLUS_MAX_OUTPUTS
#define BP_PLUS_MAX_N        64   // logN = 6, 2^6 = 64
#define BP_PLUS_LOG_N        6
#define BP_PLUS_MAX_M        16   // maxM
#define BP_PLUS_MAX_LOG_M    4    // log2(16)
#define BP_PLUS_MAX_MN       (BP_PLUS_MAX_M * BP_PLUS_MAX_N)  // 1024
#define BP_PLUS_MAX_LOG_MN   10   // log2(1024)

// Структура Bulletproofs+ (аналог rct::BulletproofPlus)
typedef struct {
    uint32_t n_V;                               // = n_amounts
    uint8_t  V[BP_PLUS_MAX_OUTPUTS][32];        // commitments

    uint8_t A[32];
    uint8_t A1[32];
    uint8_t B[32];
    uint8_t r1[32];
    uint8_t s1[32];
    uint8_t d1[32];

    uint32_t n_LR;                              // = rounds = logM + logN
    uint8_t L[BP_PLUS_MAX_LOG_MN][32];
    uint8_t R[BP_PLUS_MAX_LOG_MN][32];
} bp_plus_proof_t;

// Сгенерировать range-доказательство для amounts[]
// gamma[] — blinding factors (по одному на amount)
// out — результат
bool bp_plus_prove(const uint64_t amounts[],
                   const uint8_t gamma[][32],
                   uint32_t n_amounts,
                   bp_plus_proof_t *out);

// Освободить кэш генераторов (для повторного вызова с новым init)
void bp_plus_cleanup(void);

#endif // BP_PLUS_H