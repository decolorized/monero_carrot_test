// cw_carrot.c — см. cw_carrot.h. Порт carrot_core/enote_utils.cpp,
// payment_proposal.cpp и carrot_impl/address_device_hierarchies.cpp.
#include "cw_carrot.h"
#include "cw_crypto.h"

#include <string.h>

static const char DS_AMOUNT_BLINDING[]   = "Carrot commitment mask";
static const char DS_EXT_G_COINBASE[]    = "Carrot coinbase extension G";
static const char DS_EXT_T_COINBASE[]    = "Carrot coinbase extension T";
static const char DS_EXT_G[]             = "Carrot key extension G";
static const char DS_EXT_T[]             = "Carrot key extension T";
static const char DS_MASK_ANCHOR[]       = "Carrot encryption mask anchor";
static const char DS_MASK_AMOUNT[]       = "Carrot encryption mask a";
static const char DS_MASK_PID[]          = "Carrot encryption mask pid";
static const char DS_ANCHOR_SPECIAL[]    = "Carrot janus anchor special";
static const char DS_EPHEMERAL_PRIVKEY[] = "Carrot sending key normal";
static const char DS_VIEW_TAG[]          = "Carrot view tag";
static const char DS_SR_SECRET[]         = "Carrot sender-receiver secret";

// ---------------------------------------------------------------------------
// ключи и адреса
// ---------------------------------------------------------------------------
bool cw_keys_init(cw_keys_t *k, const uint8_t k_s[32], const uint8_t k_v[32])
{
    if (!cw_sc_is_canonical(k_s) || !cw_sc_is_canonical(k_v)) return false;
    if (cw_sc_is_zero(k_s) || cw_sc_is_zero(k_v)) return false;
    memcpy(k->k_s, k_s, 32);
    memcpy(k->k_v, k_v, 32);
    cw_pt_base(k->K_s, k_s);
    cw_pt_base(k->K_v, k_v);
    return true;
}

bool cw_subaddr_is_main(cw_subaddr_t j) { return j.major == 0 && j.minor == 0; }

void cw_addr_ext(const cw_keys_t *k, cw_subaddr_t j, uint8_t out[32])
{
    if (cw_subaddr_is_main(j)) memset(out, 0, 32);
    else cw_legacy_subaddr_ext(out, k->k_v, j.major, j.minor);
}

void cw_addr_spend_pub(const cw_keys_t *k, cw_subaddr_t j, uint8_t out[32])
{
    if (cw_subaddr_is_main(j)) { memcpy(out, k->K_s, 32); return; }
    uint8_t m[32], mG[32];
    cw_addr_ext(k, j, m);
    cw_pt_base(mG, m);
    cw_pt_add(out, mG, k->K_s);
    cw_wipe(m, sizeof(m));
}

void cw_addr_view_pub(const cw_keys_t *k, cw_subaddr_t j, uint8_t out[32])
{
    if (cw_subaddr_is_main(j)) { memcpy(out, k->K_v, 32); return; }
    uint8_t S[32];
    cw_addr_spend_pub(k, j, S);
    cw_pt_mul(out, k->k_v, S);
}

// ---------------------------------------------------------------------------
// элементарные шаги Carrot
// ---------------------------------------------------------------------------
void cw_input_context_rct(uint8_t ic[33], const uint8_t first_ki[32])
{
    ic[0] = 'R';
    memcpy(ic + 1, first_ki, 32);
}

void cw_input_context_coinbase(uint8_t ic[33], uint64_t block_index)
{
    memset(ic, 0, 33);
    ic[0] = 'C';
    for (int i = 0; i < 8; i++) ic[1 + i] = (uint8_t)(block_index >> (8 * i));
}

static void make_s_ctx(uint8_t s_ctx[32], const uint8_t s_sr[32], const uint8_t D_e[32], const uint8_t ic[33])
{
    cw_tr_t t;
    cw_tr_init(&t, DS_SR_SECRET);
    cw_tr_add(&t, D_e, 32);
    cw_tr_add(&t, ic, 33);
    cw_blake2b_carrot(s_sr, t.buf, t.n, s_ctx, 32);
    cw_tr_wipe(&t);
}

static void make_view_tag(uint8_t vt[3], const uint8_t s_sr[32], const uint8_t ic[33], const uint8_t Ko[32])
{
    cw_tr_t t;
    cw_tr_init(&t, DS_VIEW_TAG);
    cw_tr_add(&t, ic, 33);
    cw_tr_add(&t, Ko, 32);
    cw_blake2b_carrot(s_sr, t.buf, t.n, vt, 3);
}

static void make_amount_blinding(uint8_t k_a[32], const uint8_t s_ctx[32], uint64_t amount,
                                 const uint8_t spend_pub[32], int enote_type)
{
    cw_tr_t t;
    cw_tr_init(&t, DS_AMOUNT_BLINDING);
    cw_tr_u64(&t, amount);
    cw_tr_add(&t, spend_pub, 32);
    cw_tr_u8(&t, (uint8_t)enote_type);
    cw_derive_scalar(s_ctx, t.buf, t.n, k_a);
}

static void mask_bytes(uint8_t *out, size_t outlen, const char *ds, const uint8_t s_ctx[32], const uint8_t Ko[32])
{
    cw_tr_t t;
    cw_tr_init(&t, ds);
    cw_tr_add(&t, Ko, 32);
    cw_blake2b_carrot(s_ctx, t.buf, t.n, out, outlen);
}

void cw_sender_extensions(uint8_t ext_g[32], uint8_t ext_t[32], const uint8_t s_ctx[32], const uint8_t C_a[32])
{
    cw_tr_t t;
    cw_tr_init(&t, DS_EXT_G);
    cw_tr_add(&t, C_a, 32);
    cw_derive_scalar(s_ctx, t.buf, t.n, ext_g);
    cw_tr_init(&t, DS_EXT_T);
    cw_tr_add(&t, C_a, 32);
    cw_derive_scalar(s_ctx, t.buf, t.n, ext_t);
}

static bool onetime_address(uint8_t Ko[32], const uint8_t spend_pub[32],
                            const uint8_t ext_g[32], const uint8_t ext_t[32])
{
    uint8_t ext[32];
    cw_pt_gt(ext, ext_g, ext_t);
    return cw_pt_add(Ko, spend_pub, ext);
}

bool cw_ephemeral_pub(uint8_t D_e[32], const uint8_t d_e[32], const uint8_t spend_pub[32], bool is_subaddress)
{
    if (is_subaddress) return cw_ed_mul_to_x25519(D_e, d_e, spend_pub);
    cw_x25519_base(D_e, d_e);
    return true;
}

static void ephemeral_privkey(uint8_t d_e[32], const uint8_t anchor[16], const uint8_t ic[33],
                              const uint8_t spend_pub[32], const uint8_t view_pub[32], const uint8_t pid[8])
{
    cw_tr_t t;
    cw_tr_init(&t, DS_EPHEMERAL_PRIVKEY);
    cw_tr_add(&t, anchor, 16);
    cw_tr_add(&t, ic, 33);
    cw_tr_add(&t, spend_pub, 32);
    cw_tr_add(&t, view_pub, 32);
    cw_tr_add(&t, pid, 8);
    cw_derive_scalar(NULL, t.buf, t.n, d_e);
    cw_tr_wipe(&t);
}

// s_sr = d_e ConvertPointE(K^j_v), K^j_v обязан быть в подгруппе
static bool shared_key_sender(uint8_t s_sr[32], const uint8_t d_e[32], const uint8_t view_pub[32])
{
    if (!cw_pt_in_main_subgroup(view_pub)) return false;
    uint8_t X[32];
    if (!cw_ed_to_x25519(X, view_pub)) return false;
    cw_x25519(s_sr, d_e, X);
    return true;
}

// k_a, C_a, Ko, a_enc, pid_enc, vt по готовым s_sr / s^ctx_sr
static bool output_parts(cw_enote_t *e, uint8_t pid_enc[8],
                         const uint8_t s_sr[32], const uint8_t s_ctx[32],
                         const uint8_t spend_pub[32], const uint8_t pid[8],
                         uint64_t amount, int enote_type, const uint8_t ic[33])
{
    uint8_t ext_g[32], ext_t[32], m[16];
    make_amount_blinding(e->k_a, s_ctx, amount, spend_pub, enote_type);
    cw_commit(e->C_a, amount, e->k_a);
    cw_sender_extensions(ext_g, ext_t, s_ctx, e->C_a);
    bool ok = onetime_address(e->Ko, spend_pub, ext_g, ext_t);
    cw_wipe(ext_g, 32);
    cw_wipe(ext_t, 32);
    if (!ok) return false;

    mask_bytes(m, 8, DS_MASK_AMOUNT, s_ctx, e->Ko);
    for (int i = 0; i < 8; i++) e->a_enc[i] = (uint8_t)(amount >> (8 * i)) ^ m[i];
    if (pid_enc) {
        mask_bytes(m, 8, DS_MASK_PID, s_ctx, e->Ko);
        for (int i = 0; i < 8; i++) pid_enc[i] = pid[i] ^ m[i];
    }
    make_view_tag(e->view_tag, s_sr, ic, e->Ko);
    e->amount = amount;
    return true;
}

static void encrypt_anchor(uint8_t out[16], const uint8_t anchor[16], const uint8_t s_ctx[32], const uint8_t Ko[32])
{
    uint8_t m[16];
    mask_bytes(m, 16, DS_MASK_ANCHOR, s_ctx, Ko);
    for (int i = 0; i < 16; i++) out[i] = anchor[i] ^ m[i];
}

// ---------------------------------------------------------------------------
// выходы
// ---------------------------------------------------------------------------
bool cw_normal_ephemeral(uint8_t d_e[32], uint8_t D_e[32], const cw_dest_t *d,
                         const uint8_t anchor[16], const uint8_t ic[33])
{
    static const uint8_t zero_pid[8] = { 0 };
    ephemeral_privkey(d_e, anchor, ic, d->spend_pub, d->view_pub, d->has_pid ? d->pid : zero_pid);
    return cw_ephemeral_pub(D_e, d_e, d->spend_pub, d->is_subaddress);
}

bool cw_make_normal_enote(cw_enote_t *e, uint8_t pid_enc_out[8],
                          const cw_dest_t *d, uint64_t amount,
                          const uint8_t anchor[16], const uint8_t first_ki[32])
{
    static const uint8_t zero_anchor[16] = { 0 };
    static const uint8_t zero_pid[8] = { 0 };
    if (memcmp(anchor, zero_anchor, 16) == 0) return false;

    uint8_t ic[33], d_e[32], s_sr[32], s_ctx[32];
    bool ok = false;
    cw_input_context_rct(ic, first_ki);
    if (!cw_normal_ephemeral(d_e, e->D_e, d, anchor, ic)) goto done;
    if (!shared_key_sender(s_sr, d_e, d->view_pub)) goto done;
    make_s_ctx(s_ctx, s_sr, e->D_e, ic);
    if (!output_parts(e, pid_enc_out, s_sr, s_ctx, d->spend_pub, d->has_pid ? d->pid : zero_pid,
                      amount, CW_ENOTE_PAYMENT, ic)) goto done;
    encrypt_anchor(e->anchor_enc, anchor, s_ctx, e->Ko);
    memcpy(e->first_ki, first_ki, 32);
    ok = true;
done:
    cw_wipe(d_e, 32); cw_wipe(s_sr, 32); cw_wipe(s_ctx, 32);
    return ok;
}

bool cw_receiver_s_ctx(uint8_t s_ctx[32], const cw_keys_t *k, const uint8_t D_e[32], const uint8_t ic[33])
{
    uint8_t s_sr[32];
    cw_x25519(s_sr, k->k_v, D_e);
    make_s_ctx(s_ctx, s_sr, D_e, ic);
    cw_wipe(s_sr, 32);
    return true;
}

bool cw_make_special_enote(cw_enote_t *e, const cw_keys_t *k,
                           const uint8_t spend_pub[32], uint64_t amount, int enote_type,
                           const uint8_t D_e[32], const uint8_t first_ki[32])
{
    static const uint8_t zero_pid[8] = { 0 };
    uint8_t ic[33], s_sr[32], s_ctx[32], anchor[16];
    bool ok = false;
    cw_input_context_rct(ic, first_ki);
    // s_sr = k_v D_e
    cw_x25519(s_sr, k->k_v, D_e);
    make_s_ctx(s_ctx, s_sr, D_e, ic);
    if (!output_parts(e, NULL, s_sr, s_ctx, spend_pub, zero_pid, amount, enote_type, ic)) goto done;
    // anchor_sp = H_16[k_v](D_e, input_context, Ko)
    {
        cw_tr_t t;
        cw_tr_init(&t, DS_ANCHOR_SPECIAL);
        cw_tr_add(&t, D_e, 32);
        cw_tr_add(&t, ic, 33);
        cw_tr_add(&t, e->Ko, 32);
        cw_blake2b_carrot(k->k_v, t.buf, t.n, anchor, 16);
    }
    encrypt_anchor(e->anchor_enc, anchor, s_ctx, e->Ko);
    memcpy(e->D_e, D_e, 32);
    memcpy(e->first_ki, first_ki, 32);
    ok = true;
done:
    cw_wipe(s_sr, 32); cw_wipe(s_ctx, 32);
    return ok;
}

bool cw_make_coinbase_enote(cw_enote_t *e, uint8_t ext_g[32], uint8_t ext_t[32],
                            const cw_keys_t *k, uint64_t amount,
                            const uint8_t anchor[16], uint64_t block_index)
{
    static const uint8_t zero_anchor[16] = { 0 };
    static const uint8_t zero_pid[8] = { 0 };
    if (memcmp(anchor, zero_anchor, 16) == 0) return false;
    uint8_t ic[33], d_e[32], s_sr[32], s_ctx[32];
    bool ok = false;
    cw_input_context_coinbase(ic, block_index);
    ephemeral_privkey(d_e, anchor, ic, k->K_s, k->K_v, zero_pid);
    cw_x25519_base(e->D_e, d_e);
    if (!shared_key_sender(s_sr, d_e, k->K_v)) goto done;
    make_s_ctx(s_ctx, s_sr, e->D_e, ic);
    // k_a = 1
    memset(e->k_a, 0, 32);
    e->k_a[0] = 1;
    cw_commit(e->C_a, amount, e->k_a);
    {
        cw_tr_t t;
        cw_tr_init(&t, DS_EXT_G_COINBASE);
        cw_tr_u64(&t, amount);
        cw_tr_add(&t, k->K_s, 32);
        cw_derive_scalar(s_ctx, t.buf, t.n, ext_g);
        cw_tr_init(&t, DS_EXT_T_COINBASE);
        cw_tr_u64(&t, amount);
        cw_tr_add(&t, k->K_s, 32);
        cw_derive_scalar(s_ctx, t.buf, t.n, ext_t);
    }
    if (!onetime_address(e->Ko, k->K_s, ext_g, ext_t)) goto done;
    make_view_tag(e->view_tag, s_sr, ic, e->Ko);
    encrypt_anchor(e->anchor_enc, anchor, s_ctx, e->Ko);
    memset(e->a_enc, 0, 8);
    e->amount = amount;
    memset(e->first_ki, 0, 32);
    ok = true;
done:
    cw_wipe(d_e, 32); cw_wipe(s_sr, 32); cw_wipe(s_ctx, 32);
    return ok;
}

// ---------------------------------------------------------------------------
// key image
// ---------------------------------------------------------------------------
void cw_input_x(uint8_t x[32], const cw_keys_t *k, const cw_input_t *in)
{
    uint8_t m[32];
    cw_addr_ext(k, in->j, m);
    cw_sc_add(x, k->k_s, m);
    cw_sc_add(x, x, in->ext_g);
    cw_wipe(m, 32);
}

void cw_input_key_image(uint8_t L[32], const cw_keys_t *k, const cw_input_t *in)
{
    uint8_t x[32], I[32];
    cw_input_x(x, k, in);
    cw_ki_generator(I, in->O, in->biased);
    cw_pt_mul(L, x, I);
    cw_wipe(x, 32);
}
