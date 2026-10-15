// cw_carrot.h — адресация, Carrot-выходы, открытия входов и key images
// для кошелька с CryptoNote-иерархией ключей (k_s, k_v), как
// carrot::cryptonote_hierarchy_address_device + spend_device_ram_borrowed.
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t k_s[32];      // приватный spend
    uint8_t k_v[32];      // приватный view
    uint8_t K_s[32];      // k_s G
    uint8_t K_v[32];      // k_v G
} cw_keys_t;

typedef struct { uint32_t major, minor; } cw_subaddr_t;

enum { CW_ENOTE_PAYMENT = 0, CW_ENOTE_CHANGE = 1 };

// Открытый вход: всё, что нужно для key image, рерандомизации и SA/L.
// O = (k_s + k^j_subext + ext_g) G + ext_t T,  C = mask G + amount H.
typedef struct {
    uint8_t  O[32];
    uint8_t  C[32];
    uint64_t amount;
    uint8_t  mask[32];
    uint8_t  ext_g[32];
    uint8_t  ext_t[32];
    cw_subaddr_t j;
    uint8_t  biased;      // 1 — выход до Carrot (Hp как раньше)
    uint8_t  spent;       // флаг из горячего кошелька
    uint64_t global_index;
} cw_input_t;

// Carrot-выход (CarrotEnoteV1) + то, что знает отправитель
typedef struct {
    uint8_t  Ko[32];
    uint8_t  C_a[32];
    uint8_t  a_enc[8];
    uint8_t  anchor_enc[16];
    uint8_t  view_tag[3];
    uint8_t  D_e[32];
    uint8_t  first_ki[32];
    uint64_t amount;
    uint8_t  k_a[32];
} cw_enote_t;

// Получатель обычного платежа (CarrotDestinationV1)
typedef struct {
    uint8_t spend_pub[32];
    uint8_t view_pub[32];
    uint8_t is_subaddress;
    uint8_t has_pid;
    uint8_t pid[8];
} cw_dest_t;

bool cw_keys_init(cw_keys_t *k, const uint8_t k_s[32], const uint8_t k_v[32]);
bool cw_subaddr_is_main(cw_subaddr_t j);
void cw_addr_spend_pub(const cw_keys_t *k, cw_subaddr_t j, uint8_t out[32]);
void cw_addr_view_pub(const cw_keys_t *k, cw_subaddr_t j, uint8_t out[32]);
void cw_addr_ext(const cw_keys_t *k, cw_subaddr_t j, uint8_t out[32]);   // k^j_subext (0 для основного)

// input_context: 'R' || KI_1  или  'C' || block_index(8 LE) || 0...
void cw_input_context_rct(uint8_t ic[33], const uint8_t first_ki[32]);
void cw_input_context_coinbase(uint8_t ic[33], uint64_t block_index);

// Обычный платёж на внешний адрес: anchor_norm, получатель, сумма.
// pid_enc_out — зашифрованный payment id (смысл имеет только при has_pid).
bool cw_make_normal_enote(cw_enote_t *e, uint8_t pid_enc_out[8],
                          const cw_dest_t *d, uint64_t amount,
                          const uint8_t anchor[16], const uint8_t first_ki[32]);
// D_e обычного платежа (нужен для общего D_e в 2-выходной транзакции)
bool cw_normal_ephemeral(uint8_t d_e[32], uint8_t D_e[32], const cw_dest_t *d,
                         const uint8_t anchor[16], const uint8_t ic[33]);
// D_e = d_e B (основной адрес) или ConvertPointE(d_e K^j_s) (субадрес)
bool cw_ephemeral_pub(uint8_t D_e[32], const uint8_t d_e[32], const uint8_t spend_pub[32], bool is_subaddress);
// Выход себе (special self-send) с явным D_e
bool cw_make_special_enote(cw_enote_t *e, const cw_keys_t *k,
                           const uint8_t spend_pub[32], uint64_t amount, int enote_type,
                           const uint8_t D_e[32], const uint8_t first_ki[32]);
// Coinbase-выход себе (основной адрес)
bool cw_make_coinbase_enote(cw_enote_t *e, uint8_t ext_g[32], uint8_t ext_t[32],
                            const cw_keys_t *k, uint64_t amount,
                            const uint8_t anchor[16], uint64_t block_index);
// k^g_o, k^t_o для некоинбейсного выхода
void cw_sender_extensions(uint8_t ext_g[32], uint8_t ext_t[32], const uint8_t s_ctx[32], const uint8_t C_a[32]);
// s^ctx_sr из enote (получатель): k_v D_e
bool cw_receiver_s_ctx(uint8_t s_ctx[32], const cw_keys_t *k, const uint8_t D_e[32], const uint8_t ic[33]);

// x = k_s + k^j_subext + ext_g
void cw_input_x(uint8_t x[32], const cw_keys_t *k, const cw_input_t *in);
// L = x Hp(O)
void cw_input_key_image(uint8_t L[32], const cw_keys_t *k, const cw_input_t *in);

#ifdef __cplusplus
}
#endif
