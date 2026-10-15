// cw_sal.c — см. cw_sal.h
#include "cw_sal.h"
#include "cw_crypto.h"

#include <string.h>

// sum(s_i * P_i); NULL точки = G
static bool lincomb(uint8_t out[32], int n, const uint8_t *const *s, const uint8_t *const *P)
{
    uint8_t acc[32], term[32];
    for (int i = 0; i < n; i++) {
        if (!cw_pt_mul(term, s[i], P[i] ? P[i] : CW_G)) return false;
        if (i == 0) memcpy(acc, term, 32);
        else if (!cw_pt_add(acc, acc, term)) return false;
    }
    memcpy(out, acc, 32);
    return true;
}

bool cw_rerandomize(cw_rerand_t *out, const uint8_t O[32], const uint8_t C[32], bool biased_hp,
                    const uint8_t r_o[32], const uint8_t r_i[32],
                    const uint8_t r_r_i[32], const uint8_t r_c[32])
{
    uint8_t t[32], I[32];
    // O~ = O + r_o T
    if (!cw_pt_mul(t, r_o, CW_T) || !cw_pt_add(out->O_tilde, O, t)) return false;
    // I~ = Hp(O) + r_i U
    cw_ki_generator(I, O, biased_hp);
    if (!cw_pt_mul(t, r_i, CW_U) || !cw_pt_add(out->I_tilde, I, t)) return false;
    // R = r_i V + r_r_i T
    if (!cw_pt_mul2(out->R, r_i, CW_V, r_r_i, CW_T)) return false;
    // C~ = C + r_c G
    cw_pt_base(t, r_c);
    if (!cw_pt_add(out->C_tilde, C, t)) return false;
    memcpy(out->r_o, r_o, 32);
    memcpy(out->r_i, r_i, 32);
    memcpy(out->r_r_i, r_r_i, 32);
    memcpy(out->r_c, r_c, 32);
    return true;
}

static void challenge(uint8_t e[32], const uint8_t hash[32],
                      const uint8_t O_tilde[32], const uint8_t I_tilde[32],
                      const uint8_t C_tilde[32], const uint8_t R[32], const uint8_t L[32],
                      const uint8_t pts6[6 * 32])
{
    // Blake2bMonero<64>: hash || O~ || I~ || C~ || R || L || P || A || B || R_O || R_P || R_L
    uint8_t buf[32 * 12], wide[64];
    memcpy(buf, hash, 32);
    memcpy(buf + 32, O_tilde, 32);
    memcpy(buf + 64, I_tilde, 32);
    memcpy(buf + 96, C_tilde, 32);
    memcpy(buf + 128, R, 32);
    memcpy(buf + 160, L, 32);
    memcpy(buf + 192, pts6, 6 * 32);
    cw_blake2b_carrot(NULL, buf, sizeof(buf), wide, 64);
    cw_sc_reduce64(e, wide);
}

bool cw_sal_prove(uint8_t proof[CW_SAL_PROOF_SIZE], uint8_t key_image[32],
                  const uint8_t signable_tx_hash[32], const cw_rerand_t *rr,
                  const uint8_t x[32], const uint8_t y[32])
{
    bool ok = false;
    uint8_t y_t[32], chk[32], x_r_i[32], t[32];
    uint8_t alpha[32], beta[32], delta[32], mu[32], r_y[32], r_z[32], r_p[32], r_r_p[32];
    uint8_t L[32], pts[6 * 32];
    uint8_t *P = pts, *A = pts + 32, *B = pts + 64, *R_O = pts + 96, *R_P = pts + 128, *R_L = pts + 160;
    uint8_t e[32], e2[32];

    // открытие: y~ = r_o + y, проверка x G + y~ T == O~
    cw_sc_add(y_t, rr->r_o, y);
    cw_pt_gt(chk, x, y_t);
    if (!cw_pt_eq(chk, rr->O_tilde)) goto done;

    // L = x I~ - (r_i x) U
    cw_sc_mul(x_r_i, x, rr->r_i);
    {
        uint8_t xI[32], xrU[32];
        if (!cw_pt_mul(xI, x, rr->I_tilde) || !cw_pt_mul(xrU, x_r_i, CW_U)) goto done;
        if (!cw_pt_sub(L, xI, xrU)) goto done;
    }

    // нонсы: от секретов и всего входа, с подмешиванием ГСЧ
    {
        uint8_t sec[64], ctx[32 + 4 * 32];
        memcpy(sec, x, 32);
        memcpy(sec + 32, y_t, 32);
        memcpy(ctx, signable_tx_hash, 32);
        memcpy(ctx + 32, rr->O_tilde, 32);
        memcpy(ctx + 64, rr->I_tilde, 32);
        memcpy(ctx + 96, rr->R, 32);
        memcpy(ctx + 128, rr->C_tilde, 32);
        uint8_t *n[8] = { alpha, beta, delta, mu, r_y, r_z, r_p, r_r_p };
        for (uint32_t i = 0; i < 8; i++) cw_sc_hedged(n[i], sec, sizeof(sec), ctx, sizeof(ctx), 0x53414C00u + i);
        cw_wipe(sec, sizeof(sec));
    }

    // P = x G + r_i V + (x r_i) U + r_p T
    {
        const uint8_t *s[4] = { x, rr->r_i, x_r_i, r_p };
        const uint8_t *p[4] = { NULL, CW_V, CW_U, CW_T };
        if (!lincomb(P, 4, s, p)) goto done;
    }
    // A = alpha G + beta V + (alpha r_i + beta x) U + delta T
    {
        uint8_t u[32];
        cw_sc_mul(t, alpha, rr->r_i);
        cw_sc_muladd(u, beta, x, t);
        const uint8_t *s[4] = { alpha, beta, u, delta };
        const uint8_t *p[4] = { NULL, CW_V, CW_U, CW_T };
        if (!lincomb(A, 4, s, p)) goto done;
    }
    // B = (alpha beta) U + mu T
    cw_sc_mul(t, alpha, beta);
    if (!cw_pt_mul2(B, t, CW_U, mu, CW_T)) goto done;
    // R_O = alpha G + r_y T
    cw_pt_gt(R_O, alpha, r_y);
    // R_P = r_z U + r_r_p T
    if (!cw_pt_mul2(R_P, r_z, CW_U, r_r_p, CW_T)) goto done;
    // R_L = alpha I~ - r_z U
    {
        uint8_t aI[32], zU[32];
        if (!cw_pt_mul(aI, alpha, rr->I_tilde) || !cw_pt_mul(zU, r_z, CW_U)) goto done;
        if (!cw_pt_sub(R_L, aI, zU)) goto done;
    }

    challenge(e, signable_tx_hash, rr->O_tilde, rr->I_tilde, rr->C_tilde, rr->R, L, pts);
    cw_sc_mul(e2, e, e);

    memcpy(proof, pts, 6 * 32);
    uint8_t *s_alpha = proof + 192, *s_beta = proof + 224, *s_delta = proof + 256;
    uint8_t *s_y = proof + 288, *s_z = proof + 320, *s_r_p = proof + 352;
    cw_sc_muladd(s_alpha, e, x, alpha);                 // alpha + e x
    cw_sc_muladd(s_beta, e, rr->r_i, beta);             // beta + e r_i
    cw_sc_muladd(t, e, delta, mu);                      // mu + e delta
    cw_sc_muladd(s_delta, r_p, e2, t);                  // + r_p e^2
    cw_sc_muladd(s_y, e, y_t, r_y);                     // r_y + e y~
    cw_sc_muladd(s_z, e, x_r_i, r_z);                   // r_z + e x r_i
    {
        uint8_t rpp[32];
        cw_sc_sub(rpp, r_p, y_t);
        cw_sc_sub(rpp, rpp, rr->r_r_i);                 // r_p - y~ - r_r_i
        cw_sc_muladd(s_r_p, e, rpp, r_r_p);             // r_r_p + e r_p''
        cw_wipe(rpp, sizeof(rpp));
    }
    memcpy(key_image, L, 32);
    ok = true;

done:
    cw_wipe(y_t, 32); cw_wipe(x_r_i, 32); cw_wipe(t, 32);
    cw_wipe(alpha, 32); cw_wipe(beta, 32); cw_wipe(delta, 32); cw_wipe(mu, 32);
    cw_wipe(r_y, 32); cw_wipe(r_z, 32); cw_wipe(r_p, 32); cw_wipe(r_r_p, 32);
    return ok;
}

bool cw_sal_verify(const uint8_t proof[CW_SAL_PROOF_SIZE], const uint8_t hash[32],
                   const uint8_t O_tilde[32], const uint8_t I_tilde[32],
                   const uint8_t R[32], const uint8_t C_tilde[32], const uint8_t L[32])
{
    const uint8_t *P = proof, *A = proof + 32, *B = proof + 64;
    const uint8_t *R_O = proof + 96, *R_P = proof + 128, *R_L = proof + 160;
    const uint8_t *s_alpha = proof + 192, *s_beta = proof + 224, *s_delta = proof + 256;
    const uint8_t *s_y = proof + 288, *s_z = proof + 320, *s_r_p = proof + 352;

    for (int i = 0; i < 6; i++)
        if (!cw_sc_is_canonical(proof + 192 + 32 * i)) return false;
    for (int i = 0; i < 6; i++)
        if (!cw_pt_valid(proof + 32 * i)) return false;
    if (!cw_pt_valid(O_tilde) || !cw_pt_valid(I_tilde) || !cw_pt_valid(R) || !cw_pt_valid(L))
        return false;

    uint8_t e[32], e2[32], t[32], lhs[32], rhs[32];
    challenge(e, hash, O_tilde, I_tilde, C_tilde, R, L, proof);
    cw_sc_mul(e2, e, e);

    // 1) e^2 P + e A + B == (s_alpha e) G + (s_beta e) V + (s_alpha s_beta) U + s_delta T
    {
        const uint8_t one[32] = { 1 };
        const uint8_t *s[3] = { e2, e, one };
        const uint8_t *p[3] = { P, A, B };
        if (!lincomb(lhs, 3, s, p)) return false;
        uint8_t a[32], b[32], c[32];
        cw_sc_mul(a, s_alpha, e);
        cw_sc_mul(b, s_beta, e);
        cw_sc_mul(c, s_alpha, s_beta);
        const uint8_t *s2[4] = { a, b, c, s_delta };
        const uint8_t *p2[4] = { NULL, CW_V, CW_U, CW_T };
        if (!lincomb(rhs, 4, s2, p2)) return false;
        if (!cw_pt_eq(lhs, rhs)) return false;
    }
    // 2) R_O + e O~ == s_alpha G + s_y T
    if (!cw_pt_mul(t, e, O_tilde) || !cw_pt_add(lhs, R_O, t)) return false;
    cw_pt_gt(rhs, s_alpha, s_y);
    if (!cw_pt_eq(lhs, rhs)) return false;
    // 3) R_P + e (P - O~ - R) == s_z U + s_r_p T
    {
        uint8_t d[32];
        if (!cw_pt_sub(d, P, O_tilde) || !cw_pt_sub(d, d, R)) return false;
        if (!cw_pt_mul(t, e, d) || !cw_pt_add(lhs, R_P, t)) return false;
        if (!cw_pt_mul2(rhs, s_z, CW_U, s_r_p, CW_T)) return false;
        if (!cw_pt_eq(lhs, rhs)) return false;
    }
    // 4) R_L + e L == s_alpha I~ - s_z U
    {
        uint8_t aI[32], zU[32];
        if (!cw_pt_mul(t, e, L) || !cw_pt_add(lhs, R_L, t)) return false;
        if (!cw_pt_mul(aI, s_alpha, I_tilde) || !cw_pt_mul(zU, s_z, CW_U)) return false;
        if (!cw_pt_sub(rhs, aI, zU)) return false;
        if (!cw_pt_eq(lhs, rhs)) return false;
    }
    return true;
}
