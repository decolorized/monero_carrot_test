// cw_link.c — см. cw_link.h. Формат кадров совпадает с ColdPunk
// src/transfer/link.c (протокол 3) и frontend/mwlink.py.
#include "cw_link.h"
#include "cw_hotcold.h"

#include <string.h>
#include <stdio.h>

#define HDR_LEN      20
#define CRC_LEN      4
#define OVERHEAD     (HDR_LEN + CRC_LEN)
#define RX_CAP       (OVERHEAD + CW_LINK_MAX_PAYLOAD + CW_LINK_MAX_PAYLOAD / 254 + 16)

enum {
    CMD_PING = 0x01, CMD_INFO = 0x02, CMD_PUT = 0x03, CMD_GET = 0x04,
    CMD_STATUS = 0x05, CMD_CLEAR = 0x06, CMD_REQ = 0x07,
    RSP_PONG = 0x81, RSP_INFO = 0x82, RSP_ACK = 0x83, RSP_FILE = 0x84,
    RSP_STATUS = 0x85, RSP_ERROR = 0xFF, EVT_LOG = 0x90,
};
enum {
    ERR_BAD_CMD = 1, ERR_BAD_KIND = 2, ERR_TOO_BIG = 3, ERR_NOT_READY = 4,
    ERR_NO_MEMORY = 5, ERR_CRC = 6, ERR_BAD_LEN = 7, ERR_BAD_MAGIC = 8,
    ERR_BAD_FORMAT = 9, ERR_BUSY = 10, ERR_LOCKED = 11,
};
#define KIND_ALL   0xFF
#define KIND_AUTO  0xFE
#define STATE_WALLET 2
#define STATE_BUSY   3
#define CAP_SERIAL    (1u << 0)
#define CAP_AUTO_KIND (1u << 3)

static const uint8_t MAGIC[8] = { 0x4D, 0x57, 0x50, 0x4B, 0xC7, 0x3A, 0x5E, 0x91 };

typedef struct { uint8_t *data; size_t len; } slot_t;

static struct {
    bool     inited;
    uint8_t  network;
    uint8_t  reset_reason;
    uint8_t  caps;
    bool     ready;          // ключи загружены, можно принимать файлы
    char     fw[16], board[32], wallet[32];
    // приём
    uint8_t *rx;
    size_t   rx_len;
    bool     rx_overflow;
    uint8_t *hrx;            // HID: сырое сообщение
    size_t   hrx_len, hrx_expect;
    bool     hrx_in;
    // файлы
    slot_t   job;            // принятый, ещё не обработанный файл
    int      job_kind;
    bool     busy;           // job взят рабочей задачей
    bool     show_busy;      // показать BUSY хотя бы в одном STATUS после PUT
    slot_t   outbox[CW_KIND_COUNT];
    uint32_t seq;
} g;

// ---------------------------------------------------------------------------
uint32_t cw_crc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

size_t cw_link_serial_frame(const uint8_t *msg, size_t mlen, uint8_t *enc, size_t cap)
{
    if (cap < mlen + mlen / 254 + 3) return 0;
    size_t o = 0, code_at = o++;
    uint8_t code = 1;
    for (size_t i = 0; i < mlen; i++) {
        if (msg[i] == 0) {
            enc[code_at] = code;
            code_at = o++;
            code = 1;
        } else {
            enc[o++] = msg[i];
            if (++code == 0xFF) {
                enc[code_at] = code;
                code_at = o++;
                code = 1;
            }
        }
    }
    enc[code_at] = code;
    enc[o++] = 0x00;
    return o;
}

size_t cw_link_hid_report_count(size_t len)
{
    if (len <= CW_LINK_HID_FIRST) return 1;
    return 1 + (len - CW_LINK_HID_FIRST + CW_LINK_HID_CONT - 1) / CW_LINK_HID_CONT;
}

void cw_link_hid_report(const uint8_t *msg, size_t len, size_t idx, uint8_t out[CW_LINK_HID_DATA])
{
    memset(out, 0, CW_LINK_HID_DATA);
    size_t off, take, hdr;
    if (idx == 0) { out[0] = '?'; out[1] = '#'; out[2] = '#'; hdr = 3; off = 0; take = CW_LINK_HID_FIRST; }
    else { out[0] = '?'; hdr = 1; off = CW_LINK_HID_FIRST + (idx - 1) * CW_LINK_HID_CONT; take = CW_LINK_HID_CONT; }
    if (off >= len) return;
    if (take > len - off) take = len - off;
    memcpy(out + hdr, msg + off, take);
}

// ответ уходит в транспорт запроса, события — во все активные
static void send_to(int transport, uint8_t cmd, uint8_t arg, const uint8_t *payload, size_t len)
{
    size_t mlen = OVERHEAD + len;
    uint8_t *msg = (uint8_t *)cw_malloc(mlen);
    if (!msg) return;
    memcpy(msg, MAGIC, 8);
    msg[8] = CW_LINK_PROTO;
    msg[9] = cmd;
    msg[10] = arg;
    msg[11] = 0;
    put_u32(msg + 12, (uint32_t)len);
    put_u32(msg + 16, cw_crc32(msg, 16));
    if (len) memcpy(msg + HDR_LEN, payload, len);
    put_u32(msg + HDR_LEN + len, cw_crc32(msg, HDR_LEN + len));
    cw_link_send(transport, msg, mlen);
    cw_free(msg);
}

static int g_cur_tr = CW_TR_SERIAL;
static void send_msg(uint8_t cmd, uint8_t arg, const uint8_t *payload, size_t len)
{
    send_to(g_cur_tr, cmd, arg, payload, len);
}

static void send_error(uint8_t code, const char *text)
{
    send_msg(RSP_ERROR, code, (const uint8_t *)text, text ? strlen(text) : 0);
}

void cw_link_log(int level, const char *text)
{
    if (!g.inited) return;
    size_t n = strlen(text);
    if (n > 512) n = 512;
    send_to(CW_TR_EVENT, EVT_LOG, (uint8_t)level, (const uint8_t *)text, n);
}

// ---------------------------------------------------------------------------
bool cw_link_init(uint8_t network, const char *fw, const char *board, const char *wallet)
{
    memset(&g, 0, sizeof(g));
    g.rx = (uint8_t *)cw_malloc(RX_CAP);
    g.hrx = (uint8_t *)cw_malloc(OVERHEAD + CW_LINK_MAX_PAYLOAD);
    if (!g.rx || !g.hrx) return false;
    g.network = network;
    strncpy(g.fw, fw, sizeof(g.fw) - 1);
    strncpy(g.board, board, sizeof(g.board) - 1);
    strncpy(g.wallet, wallet, sizeof(g.wallet) - 1);
    g.caps = CAP_SERIAL;
    g.inited = true;
    return true;
}

void cw_link_set_reset_reason(uint8_t r) { g.reset_reason = r; }
void cw_link_set_caps(uint8_t caps) { g.caps = caps; }
void cw_link_set_ready(bool ready) { cw_link_lock(); g.ready = ready; cw_link_unlock(); }

static uint8_t state_now(void) { return (!g.ready || g.job.data || g.busy || g.show_busy) ? STATE_BUSY : STATE_WALLET; }
static uint8_t accept_mask(void) { return (1u << CW_KIND_OUTPUTS) | (1u << CW_KIND_UNSIGNED); }

static void reply_info(void)
{
    uint8_t p[128];
    memset(p, 0, sizeof(p));
    p[0] = CW_LINK_PROTO;
    p[1] = (uint8_t)(g.caps | CAP_AUTO_KIND);
    cw_link_lock();
    p[2] = state_now();
    cw_link_unlock();
    p[3] = g.network;
    put_u32(p + 4, CW_LINK_MAX_PAYLOAD);
    p[8] = 1;               // wallets
    p[9] = 1;               // unlocked
    p[10] = 0;
    p[11] = CW_KIND_COUNT;
    memcpy(p + 12, g.fw, strlen(g.fw));
    memcpy(p + 28, g.board, strlen(g.board));
    memcpy(p + 60, g.wallet, strlen(g.wallet));
    p[92] = g.reset_reason;
    send_msg(RSP_INFO, 0, p, sizeof(p));
}

static void reply_status(void)
{
    uint8_t p[48];
    memset(p, 0, sizeof(p));
    cw_link_lock();
    if (g.job.data) put_u32(p + 4 * g.job_kind, (uint32_t)g.job.len);
    for (int i = 0; i < CW_KIND_COUNT; i++) put_u32(p + 20 + 4 * i, (uint32_t)g.outbox[i].len);
    p[40] = state_now();
    // Файл обрабатывается быстрее, чем хост опрашивает STATUS: без этого хост
    // не увидел бы BUSY и не понял бы, что файл отклонён (mwlink _track_declines).
    if (g.ready && !g.job.data && !g.busy) g.show_busy = false;
    p[41] = 0;
    p[42] = accept_mask();
    put_u32(p + 44, g.seq);
    cw_link_unlock();
    send_msg(RSP_STATUS, 0, p, sizeof(p));
}

static int classify(const uint8_t *d, size_t n, char *why, size_t why_len)
{
    int ver = 0;
    int kind = cw_detect_file(d, n, &ver);
    switch (kind) {
    case CW_FILE_OUTPUTS:
        if (ver == 4 || ver == 5) return CW_KIND_OUTPUTS;
        snprintf(why, why_len, "outputs file version %d is not supported", ver);
        return -1;
    case CW_FILE_UNSIGNED:
        if (ver == 6) return CW_KIND_UNSIGNED;
        snprintf(why, why_len, "unsigned tx set version %d: this device signs only FCMP++/Carrot sets (version 6)", ver);
        return -1;
    case CW_FILE_KEYIMAGES:
        snprintf(why, why_len, "this is a key images file: import it into the view-only wallet");
        return -1;
    case CW_FILE_SIGNED:
        snprintf(why, why_len, "this is a signed tx set: load it into the view-only wallet and send it");
        return -1;
    }
    snprintf(why, why_len, "not a Monero exchange file");
    return -1;
}

static void reply_put(uint8_t arg, const uint8_t *payload, size_t len)
{
    if (len == 0) { send_error(ERR_BAD_LEN, "empty file"); return; }
    char why[128] = "";
    int kind = classify(payload, len, why, sizeof(why));
    if (arg != KIND_AUTO && arg >= CW_KIND_COUNT) { send_error(ERR_BAD_KIND, "bad file kind"); return; }
    if (kind < 0) { send_error(ERR_BAD_FORMAT, why); return; }
    if (arg != KIND_AUTO && arg != kind) { send_error(ERR_LOCKED, "the device does not accept this file type"); return; }

    uint8_t *copy = (uint8_t *)cw_malloc(len);
    if (!copy) { send_error(ERR_NO_MEMORY, "no memory for file"); return; }
    memcpy(copy, payload, len);

    cw_link_lock();
    if (!g.ready) {
        cw_link_unlock();
        cw_free(copy);
        send_error(ERR_BUSY, "the device is starting: keys are being loaded");
        return;
    }
    if (g.job.data || g.busy) {
        cw_link_unlock();
        cw_free(copy);
        send_error(ERR_BUSY, "the device is still processing the previous file");
        return;
    }
    g.job.data = copy;
    g.job.len = len;
    g.job_kind = kind;
    g.show_busy = true;
    g.seq++;
    cw_link_unlock();

    send_msg(RSP_ACK, (uint8_t)kind, NULL, 0);
    cw_link_job_signal();
}

static void handle(const uint8_t *m, size_t n, int transport)
{
    g_cur_tr = transport;
    if (n < OVERHEAD || memcmp(m, MAGIC, 8) != 0 || m[8] != CW_LINK_PROTO) {
        send_error(ERR_BAD_MAGIC, "bad magic");
        return;
    }
    if (get_u32(m + 16) != cw_crc32(m, 16)) { send_error(ERR_CRC, "header crc mismatch"); return; }
    uint32_t plen = get_u32(m + 12);
    if (plen > CW_LINK_MAX_PAYLOAD) { send_error(ERR_TOO_BIG, "payload too large"); return; }
    if ((size_t)plen + OVERHEAD != n) { send_error(ERR_BAD_LEN, "length mismatch"); return; }
    if (get_u32(m + HDR_LEN + plen) != cw_crc32(m, HDR_LEN + plen)) { send_error(ERR_CRC, "crc mismatch"); return; }

    uint8_t cmd = m[9], arg = m[10];
    const uint8_t *payload = m + HDR_LEN;
    switch (cmd) {
    case CMD_PING:
        send_msg(RSP_PONG, arg, payload, plen > 256 ? 256 : plen);
        break;
    case CMD_INFO:
        reply_info();
        break;
    case CMD_STATUS:
        reply_status();
        break;
    case CMD_PUT:
        reply_put(arg, payload, plen);
        break;
    case CMD_GET: {
        if (arg >= CW_KIND_COUNT) { send_error(ERR_BAD_KIND, "bad file kind"); break; }
        cw_link_lock();
        slot_t s = g.outbox[arg];
        uint8_t *copy = s.data ? (uint8_t *)cw_malloc(s.len) : NULL;
        if (copy) memcpy(copy, s.data, s.len);
        cw_link_unlock();
        if (!s.data) { send_error(ERR_NOT_READY, "outbox empty"); break; }
        if (!copy) { send_error(ERR_NO_MEMORY, "reply buffer"); break; }
        send_msg(RSP_FILE, arg, copy, s.len);
        cw_free(copy);
        break;
    }
    case CMD_CLEAR: {
        if (arg != KIND_ALL && arg >= CW_KIND_COUNT) { send_error(ERR_BAD_KIND, "bad file kind"); break; }
        cw_link_lock();
        for (int i = 0; i < CW_KIND_COUNT; i++) {
            if (arg != KIND_ALL && arg != i) continue;
            if (g.outbox[i].data) cw_free(g.outbox[i].data);
            g.outbox[i].data = NULL;
            g.outbox[i].len = 0;
        }
        cw_link_unlock();
        send_msg(RSP_ACK, arg, NULL, 0);
        break;
    }
    case CMD_REQ:
        send_error(ERR_BAD_CMD, "requests are not supported by this firmware");
        break;
    default:
        send_error(ERR_BAD_CMD, "unknown command");
    }
}

// COBS-декодирование на месте; false — испорченный кадр
static bool cobs_decode_inplace(uint8_t *b, size_t n, size_t *out_len)
{
    size_t i = 0, o = 0;
    while (i < n) {
        uint8_t code = b[i++];
        if (code == 0) return false;
        size_t run = code - 1u;
        if (i + run > n) return false;
        memmove(b + o, b + i, run);
        o += run;
        i += run;
        if (code != 0xFF && i < n) b[o++] = 0;
    }
    *out_len = o;
    return true;
}

void cw_link_feed_serial(const uint8_t *data, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t c = data[i];
        if (c != 0) {
            if (g.rx_len < RX_CAP) g.rx[g.rx_len++] = c;
            else g.rx_overflow = true;
            continue;
        }
        if (g.rx_len && !g.rx_overflow) {
            size_t ml;
            if (cobs_decode_inplace(g.rx, g.rx_len, &ml)) handle(g.rx, ml, CW_TR_SERIAL);
        }
        g.rx_len = 0;
        g.rx_overflow = false;
    }
}

static bool hdr_valid(const uint8_t *h, uint32_t *plen)
{
    if (memcmp(h, MAGIC, 8) != 0 || h[8] != CW_LINK_PROTO) return false;
    if (get_u32(h + 16) != cw_crc32(h, 16)) return false;
    *plen = get_u32(h + 12);
    return *plen <= CW_LINK_MAX_PAYLOAD;
}

void cw_link_feed_hid(const uint8_t rep[CW_LINK_HID_DATA])
{
    uint32_t plen;
    if (rep[0] == '?' && rep[1] == '#' && rep[2] == '#' && hdr_valid(rep + 3, &plen)) {
        g.hrx_in = true;
        g.hrx_expect = OVERHEAD + plen;
        g.hrx_len = 0;
        size_t take = CW_LINK_HID_FIRST < g.hrx_expect ? CW_LINK_HID_FIRST : g.hrx_expect;
        memcpy(g.hrx, rep + 3, take);
        g.hrx_len = take;
    } else if (rep[0] == '?' && g.hrx_in) {
        size_t take = g.hrx_expect - g.hrx_len;
        if (take > CW_LINK_HID_CONT) take = CW_LINK_HID_CONT;
        memcpy(g.hrx + g.hrx_len, rep + 1, take);
        g.hrx_len += take;
    } else {
        return;
    }
    if (g.hrx_in && g.hrx_len >= g.hrx_expect) {
        g.hrx_in = false;
        handle(g.hrx, g.hrx_expect, CW_TR_HID);
    }
}

bool cw_link_job_take(int *kind, uint8_t **data, size_t *len)
{
    cw_link_lock();
    bool have = g.job.data != NULL && !g.busy;
    if (have) {
        *kind = g.job_kind;
        *data = g.job.data;
        *len = g.job.len;
        g.job.data = NULL;
        g.job.len = 0;
        g.busy = true;
    }
    cw_link_unlock();
    return have;
}

void cw_link_job_done(int out_kind, uint8_t *data, size_t len)
{
    cw_link_job_done2(out_kind, data, len, -1, NULL, 0);
}

static void outbox_set(int kind, uint8_t *data, size_t len)
{
    if (data && kind >= 0 && kind < CW_KIND_COUNT) {
        if (g.outbox[kind].data) cw_free(g.outbox[kind].data);
        g.outbox[kind].data = data;
        g.outbox[kind].len = len;
    } else if (data) {
        cw_free(data);
    }
}

void cw_link_job_done2(int kind1, uint8_t *data1, size_t len1, int kind2, uint8_t *data2, size_t len2)
{
    cw_link_lock();
    outbox_set(kind1, data1, len1);
    outbox_set(kind2, data2, len2);
    g.busy = false;
    g.seq++;
    cw_link_unlock();
}

