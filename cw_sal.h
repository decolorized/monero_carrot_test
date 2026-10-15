// cw_sal.h — FCMP++ Spend-Authorization & Linkability (SA/L) и рерандомизация
// входов. Порт monero-oxide/ringct/fcmp++/src/sal/mod.rs (rev 31c26d9) и
// monero src/fcmp_pp/prove.cpp.
#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CW_SAL_PROOF_SIZE (12 * 32)

// FcmpRerandomizedOutputCompressed: O~, I~, R, C~, r_o, r_i, r_r_i, r_c
typedef struct {
    uint8_t O_tilde[32];
    uint8_t I_tilde[32];
    uint8_t R[32];
    uint8_t C_tilde[32];
    uint8_t r_o[32];
    uint8_t r_i[32];
    uint8_t r_r_i[32];
    uint8_t r_c[32];
} cw_rerand_t;

// O~ = O + r_o T, I~ = Hp(O) + r_i U, R = r_i V + r_r_i T, C~ = C + r_c G
bool cw_rerandomize(cw_rerand_t *out, const uint8_t O[32], const uint8_t C[32], bool biased_hp,
                    const uint8_t r_o[32], const uint8_t r_i[32],
                    const uint8_t r_r_i[32], const uint8_t r_c[32]);

// Доказательство для выхода O = x G + y T. Возвращает key image L = x Hp(O).
bool cw_sal_prove(uint8_t proof[CW_SAL_PROOF_SIZE], uint8_t key_image[32],
                  const uint8_t signable_tx_hash[32], const cw_rerand_t *rr,
                  const uint8_t x[32], const uint8_t y[32]);

// Проверка (без пакетной проверки, все четыре уравнения по отдельности).
bool cw_sal_verify(const uint8_t proof[CW_SAL_PROOF_SIZE], const uint8_t signable_tx_hash[32],
                   const uint8_t O_tilde[32], const uint8_t I_tilde[32],
                   const uint8_t R[32], const uint8_t C_tilde[32], const uint8_t key_image[32]);

#ifdef __cplusplus
}
#endif
