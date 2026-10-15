// cw_esp32.cpp — платформа ESP32-S3 (Arduino core 3.x):
//   * USB-транспорты протокола mwlink 3: Serial (CDC) и vendor HID —
//     перенесено из ColdPunk src/transfer/usb_link_arduino.cpp;
//   * рабочая задача: загрузка ключей, подпись, экспорт key images;
//   * хранилище открытых входов на LittleFS;
//   * ГСЧ, память в PSRAM, журнал устройства.
//
// Serial (COBS + CRC32) работает при любом Tools > USB Mode. HID есть только
// в режиме USB-OTG (TinyUSB). Фронтенд ищет устройство по VID 0x303A и
// PID 0x4024/0x4025/0x1001.
#include <Arduino.h>
#include <LittleFS.h>
#include <esp_random.h>
#include <esp_system.h>
#include <esp_heap_caps.h>
#include <esp_partition.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

#include <stdarg.h>
#include <string.h>

extern "C" {
#include "cw_link.h"
#include "cw_hotcold.h"
#include "cw_crypto.h"
void bootloader_random_enable(void);
}
#include "cw_config.h"
#if __has_include("secrets.h")
#  include "secrets.h"
#else
#  error "secrets.h not found: copy secrets.example.h to secrets.h and put your wallet keys there"
#endif
// необязательные поля secrets.h (старые версии файла их не содержат)
#ifndef SPEND_PUBLIC_KEY_HEX
#  define SPEND_PUBLIC_KEY_HEX ""
#endif
#ifndef VIEW_PUBLIC_KEY_HEX
#  define VIEW_PUBLIC_KEY_HEX ""
#endif
#ifndef WALLET_NETWORK
#  define WALLET_NETWORK 0
#endif
#ifndef WALLET_NAME
#  define WALLET_NAME "MoneroCarrot"
#endif

#if defined(ARDUINO_USB_MODE) && (ARDUINO_USB_MODE == 0) && CW_USE_HID
#  include <USB.h>
#  include <USBHID.h>
#  define CW_HAVE_HID 1
#else
#  define CW_HAVE_HID 0
#endif

// ===========================================================================
// память, ГСЧ, журнал
// ===========================================================================
extern "C" void *cw_malloc(size_t n)
{
    void *p = heap_caps_malloc(n ? n : 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = malloc(n ? n : 1);
    return p;
}

extern "C" void cw_free(void *p) { free(p); }

extern "C" void cw_random(uint8_t *buf, size_t n) { esp_fill_random(buf, n); }

static void vlog(int level, const char *fmt, va_list ap)
{
    char line[200];
    vsnprintf(line, sizeof(line), fmt, ap);
    cw_link_log(level, line);
}

extern "C" void cw_log(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vlog(CW_LOG_INFO, fmt, ap); va_end(ap);
}

extern "C" void cw_progress(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vlog(CW_LOG_PROGRESS, fmt, ap); va_end(ap);
}

static void log_error(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vlog(CW_LOG_ERROR, fmt, ap); va_end(ap);
}

// slow-hash.c
extern "C" void platform_log(const char *msg) { cw_link_log(CW_LOG_DEBUG, msg); }

// ===========================================================================
// хранилище открытых входов: /cw_inputs.bin, записи фиксированного размера
// ===========================================================================
static const char *STORE_PATH = "/cw_inputs.bin";
static const uint32_t STORE_MAGIC = 0x43574931;   // "CWI1"
static cw_input_t *g_store;
static size_t g_store_n, g_store_cap;
static bool g_fs_ok;
static char g_fs_label[17];

// LittleFS живёт в первом data-разделе подтипа spiffs, как бы он ни назывался:
// у "Default ... with spiffs" он "spiffs", в partitions.csv этого проекта — "storage".
static bool fs_mount()
{
    const esp_partition_t *p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                        ESP_PARTITION_SUBTYPE_DATA_SPIFFS, NULL);
    if (!p) return false;
    strncpy(g_fs_label, p->label, sizeof(g_fs_label) - 1);
    return LittleFS.begin(true, "/littlefs", 4, g_fs_label);
}

static void store_load()
{
    g_store_cap = 256;
    g_store = (cw_input_t *)cw_malloc(sizeof(cw_input_t) * g_store_cap);
    g_store_n = 0;
    if (!g_fs_ok) return;
    File f = LittleFS.open(STORE_PATH, "r");
    if (!f) return;
    uint32_t magic = 0, rec = 0;
    if (f.read((uint8_t *)&magic, 4) != 4 || f.read((uint8_t *)&rec, 4) != 4 ||
        magic != STORE_MAGIC || rec != sizeof(cw_input_t)) {
        f.close();
        LittleFS.remove(STORE_PATH);
        return;
    }
    cw_input_t in;
    while (f.read((uint8_t *)&in, sizeof(in)) == sizeof(in)) {
        if (g_store_n == g_store_cap) {
            size_t nc = g_store_cap * 2;
            cw_input_t *ns = (cw_input_t *)cw_malloc(sizeof(cw_input_t) * nc);
            if (!ns) break;
            memcpy(ns, g_store, sizeof(cw_input_t) * g_store_n);
            cw_free(g_store);
            g_store = ns;
            g_store_cap = nc;
        }
        g_store[g_store_n++] = in;
    }
    f.close();
}

extern "C" bool cw_store_find(const uint8_t O[32], cw_input_t *out)
{
    for (size_t i = 0; i < g_store_n; i++)
        if (memcmp(g_store[i].O, O, 32) == 0) { *out = g_store[i]; return true; }
    return false;
}

extern "C" void cw_store_put(const cw_input_t *in)
{
    for (size_t i = 0; i < g_store_n; i++) {
        if (memcmp(g_store[i].O, in->O, 32) != 0) continue;
        if (memcmp(&g_store[i], in, sizeof(*in)) == 0) return;
        g_store[i] = *in;
        if (g_fs_ok) {                      // перезаписать на месте
            File f = LittleFS.open(STORE_PATH, "r+");
            if (f) { f.seek(8 + i * sizeof(*in)); f.write((const uint8_t *)in, sizeof(*in)); f.close(); }
        }
        return;
    }
    if (g_store_n == g_store_cap) {
        size_t nc = g_store_cap * 2;
        cw_input_t *ns = (cw_input_t *)cw_malloc(sizeof(cw_input_t) * nc);
        if (!ns) return;
        memcpy(ns, g_store, sizeof(cw_input_t) * g_store_n);
        cw_free(g_store);
        g_store = ns;
        g_store_cap = nc;
    }
    g_store[g_store_n++] = *in;
    if (!g_fs_ok) return;
    bool fresh = !LittleFS.exists(STORE_PATH);
    File f = LittleFS.open(STORE_PATH, "a");
    if (!f) return;
    if (fresh) {
        uint32_t hdr[2] = { STORE_MAGIC, (uint32_t)sizeof(cw_input_t) };
        f.write((const uint8_t *)hdr, 8);
    }
    f.write((const uint8_t *)in, sizeof(*in));
    f.close();
}

// ===========================================================================
// USB: HID-устройство и кольцо входящих отчётов (как в ColdPunk)
// ===========================================================================
#if CW_HAVE_HID
static const uint8_t HID_REPORT_DESC[] = {
    0x06, 0x00, 0xFF,               // Usage Page (Vendor 0xFF00)
    0x09, 0x01,                     // Usage (1)
    0xA1, 0x01,                     // Collection (Application)
    0x85, 0x01,                     //   Report ID 1
    0x09, 0x02,                     //   Usage (2)  device -> host
    0x15, 0x00, 0x26, 0xFF, 0x00,   //   Logical 0..255
    0x75, 0x08, 0x95, CW_LINK_HID_DATA,
    0x81, 0x02,                     //   Input
    0x09, 0x03,                     //   Usage (3)  host -> device
    0x15, 0x00, 0x26, 0xFF, 0x00,
    0x75, 0x08, 0x95, CW_LINK_HID_DATA,
    0x91, 0x02,                     //   Output
    0xC0
};

static const size_t HID_RING_SLOTS = 128;
static struct {
    uint8_t slot[HID_RING_SLOTS][CW_LINK_HID_DATA];
    volatile uint32_t head, tail;
} g_ring;
static portMUX_TYPE g_ring_mux = portMUX_INITIALIZER_UNLOCKED;

static void ring_push(const uint8_t *d, size_t n)
{
    portENTER_CRITICAL(&g_ring_mux);
    uint32_t next = (g_ring.head + 1) % HID_RING_SLOTS;
    if (next != g_ring.tail) {
        memset(g_ring.slot[g_ring.head], 0, CW_LINK_HID_DATA);
        memcpy(g_ring.slot[g_ring.head], d, n < CW_LINK_HID_DATA ? n : CW_LINK_HID_DATA);
        g_ring.head = next;
    }
    portEXIT_CRITICAL(&g_ring_mux);
}

static bool ring_pop(uint8_t out[CW_LINK_HID_DATA])
{
    bool ok = false;
    portENTER_CRITICAL(&g_ring_mux);
    if (g_ring.tail != g_ring.head) {
        memcpy(out, g_ring.slot[g_ring.tail], CW_LINK_HID_DATA);
        g_ring.tail = (g_ring.tail + 1) % HID_RING_SLOTS;
        ok = true;
    }
    portEXIT_CRITICAL(&g_ring_mux);
    return ok;
}

static USBHID g_hid;

class CwHidLink : public USBHIDDevice {
public:
    CwHidLink() { g_hid.addDevice(this, sizeof(HID_REPORT_DESC)); }
    uint16_t _onGetDescriptor(uint8_t *dst) override
    {
        memcpy(dst, HID_REPORT_DESC, sizeof(HID_REPORT_DESC));
        return sizeof(HID_REPORT_DESC);
    }
    void _onOutput(uint8_t report_id, const uint8_t *buffer, uint16_t len) override
    {
        (void)report_id;
        if (!buffer || len == 0) return;
        if (len > CW_LINK_HID_DATA && buffer[0] == 0x01) { buffer++; len--; }
        ring_push(buffer, len);
    }
};
static CwHidLink g_hid_dev;
#endif

// ===========================================================================
// отправка
// ===========================================================================
static SemaphoreHandle_t g_box_mutex, g_tx_mutex;
static uint8_t *g_tx_frame;
static size_t g_tx_frame_cap;
static volatile uint32_t g_last_serial_rx, g_last_hid_rx;
static const uint32_t HOST_ACTIVE_MS = 30000;

extern "C" void cw_link_lock(void) { xSemaphoreTake(g_box_mutex, portMAX_DELAY); }
extern "C" void cw_link_unlock(void) { xSemaphoreGive(g_box_mutex); }

static bool host_active(uint32_t t) { return t != 0 && (millis() - t) < HOST_ACTIVE_MS; }

static bool send_serial(const uint8_t *msg, size_t len, uint32_t deadline_ms)
{
    size_t need = len + len / 254 + 3;
    if (need > g_tx_frame_cap) {
        uint8_t *nb = (uint8_t *)cw_malloc(need);
        if (!nb) return false;
        cw_free(g_tx_frame);
        g_tx_frame = nb;
        g_tx_frame_cap = need;
    }
    size_t n = cw_link_serial_frame(msg, len, g_tx_frame, g_tx_frame_cap);
    uint32_t t0 = millis();
    size_t done = 0;
    while (done < n) {
        size_t w = Serial.write(g_tx_frame + done, n - done);
        done += w;
        if (done >= n) break;
        if (millis() - t0 > deadline_ms) { g_last_serial_rx = 0; return false; }
        if (w == 0) vTaskDelay(pdMS_TO_TICKS(1));
    }
    Serial.flush();
    return true;
}

#if CW_HAVE_HID
static bool send_hid(const uint8_t *msg, size_t len, uint32_t deadline_ms)
{
    uint8_t rep[CW_LINK_HID_DATA];
    size_t k = cw_link_hid_report_count(len);
    uint32_t t0 = millis();
    for (size_t i = 0; i < k; i++) {
        cw_link_hid_report(msg, len, i, rep);
        while (!g_hid.SendReport(0x01, rep, CW_LINK_HID_DATA, 250)) {
            if (millis() - t0 > deadline_ms) { g_last_hid_rx = 0; return false; }
            vTaskDelay(pdMS_TO_TICKS(2));
        }
    }
    return true;
}
#endif

extern "C" void cw_link_send(int transport, const uint8_t *msg, size_t len)
{
    xSemaphoreTake(g_tx_mutex, portMAX_DELAY);
    if (transport == CW_TR_SERIAL) {
        send_serial(msg, len, 5000);
    }
#if CW_HAVE_HID
    else if (transport == CW_TR_HID) {
        send_hid(msg, len, 5000);
    }
#endif
    else if (transport == CW_TR_EVENT) {
        // журнал: только тем, кто недавно что-то спрашивал; не задерживать
        if (host_active(g_last_serial_rx)) send_serial(msg, len, 100);
#if CW_HAVE_HID
        if (host_active(g_last_hid_rx)) send_hid(msg, len, 100);
#endif
    }
    xSemaphoreGive(g_tx_mutex);
}

// ===========================================================================
// рабочая задача
// ===========================================================================
static TaskHandle_t g_worker;
static cw_wallet_t *g_wallet;

extern "C" void cw_link_job_signal(void) { if (g_worker) xTaskNotifyGive(g_worker); }

static bool hex32(const char *h, uint8_t out[32])
{
    if (strlen(h) != 64) return false;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

static bool rng_selftest()
{
    uint32_t w[32];
    for (int i = 0; i < 32; i++) w[i] = esp_random();
    uint32_t any = 0, all = 0xFFFFFFFFu;
    for (int i = 0; i < 32; i++) { any |= w[i]; all &= w[i]; }
    if (any == 0 || all == 0xFFFFFFFFu) return false;
    for (int i = 0; i < 32; i++)
        for (int j = i + 1; j < 32; j++)
            if (w[i] == w[j]) return false;
    return true;
}

static bool load_wallet()
{
    uint8_t ks[32], kv[32];
    if (!hex32(SPEND_SECRET_KEY_HEX, ks) || !hex32(VIEW_SECRET_KEY_HEX, kv)) {
        log_error("secrets.h: SPEND_SECRET_KEY_HEX / VIEW_SECRET_KEY_HEX must be 64 hex characters");
        return false;
    }
    g_wallet = (cw_wallet_t *)cw_malloc(sizeof(cw_wallet_t));
    if (!g_wallet) return false;
    cw_progress("loading keys (cn_slow_hash, a few seconds)...");
    uint32_t t0 = millis();
    bool ok = cw_wallet_init(g_wallet, ks, kv);
    cw_wipe(ks, 32);
    cw_wipe(kv, 32);
    if (!ok) { log_error("secrets.h: invalid private keys"); return false; }
    uint8_t pub[32];
    if (strlen(SPEND_PUBLIC_KEY_HEX) && (!hex32(SPEND_PUBLIC_KEY_HEX, pub) || !cw_pt_eq(pub, g_wallet->keys.K_s))) {
        log_error("secrets.h: SPEND_PUBLIC_KEY_HEX does not match the private spend key");
        return false;
    }
    if (strlen(VIEW_PUBLIC_KEY_HEX) && (!hex32(VIEW_PUBLIC_KEY_HEX, pub) || !cw_pt_eq(pub, g_wallet->keys.K_v))) {
        log_error("secrets.h: VIEW_PUBLIC_KEY_HEX does not match the private view key");
        return false;
    }
    cw_log("keys loaded in %u ms, %u known outputs", (unsigned)(millis() - t0), (unsigned)g_store_n);
    if (!g_fs_ok)
        log_error("no LittleFS partition: known outputs are kept in RAM only and are forgotten "
                  "on restart (use partitions.csv from the project or a scheme with SPIFFS)");
    return true;
}

static void worker_task(void *)
{
    if (!rng_selftest()) {
        log_error("RNG self-test failed: signing is disabled");
        for (;;) vTaskDelay(pdMS_TO_TICKS(10000));
    }
    if (!load_wallet()) {
        for (;;) { vTaskDelay(pdMS_TO_TICKS(10000)); log_error("keys are not loaded: fix secrets.h and reflash"); }
    }
    cw_link_set_ready(true);
    cw_progress("ready: send an outputs file or an unsigned tx set");

    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
        int kind;
        uint8_t *data;
        size_t len;
        while (cw_link_job_take(&kind, &data, &len)) {
            uint8_t *out = NULL, *ki = NULL;
            size_t out_len = 0, ki_len = 0;
            char err[160] = "";
            uint32_t t0 = millis();
            bool ok;
            int out_kind;
            if (!g_fs_ok)
                log_error("no LittleFS partition: outputs seen by the device are forgotten on restart");
            if (kind == CW_KIND_UNSIGNED) {
                cw_progress("signing %u bytes...", (unsigned)len);
                ok = cw_sign_unsigned_set2(g_wallet, data, len, &out, &out_len, &ki, &ki_len, err, sizeof(err));
                out_kind = CW_KIND_SIGNED;
            } else {
                cw_progress("exporting key images from %u bytes...", (unsigned)len);
                ok = cw_export_key_images(g_wallet, data, len, &out, &out_len, err, sizeof(err));
                out_kind = CW_KIND_KEYIMAGES;
            }
            cw_free(data);
            if (ok) cw_progress("done in %u ms: %u bytes", (unsigned)(millis() - t0), (unsigned)out_len);
            else log_error("refused: %s", err);
            if (ok && ki) cw_link_job_done2(out_kind, out, out_len, CW_KIND_KEYIMAGES, ki, ki_len);
            else cw_link_job_done(out_kind, ok ? out : NULL, out_len);
        }
    }
}

// ===========================================================================
// входная точка из .ino
// ===========================================================================
extern "C" void cw_platform_setup(void)
{
    // ГСЧ: без RF на ESP32-S3 настоящая энтропия только с SAR ADC.
    // bootloader_random_disable() не вызывать: нонсы подписи берутся отсюда.
    bootloader_random_enable();

    g_box_mutex = xSemaphoreCreateMutex();
    g_tx_mutex = xSemaphoreCreateMutex();

    Serial.begin(115200);
    Serial.setTimeout(5);

    g_fs_ok = fs_mount();
    store_load();

    cw_link_init(WALLET_NETWORK, CW_FW_VERSION, CW_BOARD_NAME, WALLET_NAME);
    uint8_t caps = CW_LINK_CAP_SERIAL;
#if CW_HAVE_HID
    memset(&g_ring, 0, sizeof(g_ring));
    g_hid.begin();
    caps |= CW_LINK_CAP_HID;
#  if !(defined(ARDUINO_USB_CDC_ON_BOOT) && (ARDUINO_USB_CDC_ON_BOOT == 1))
    USB.VID(0x303A);
    USB.PID(0x4024);
    USB.manufacturerName("Monero");
    USB.productName("Cold Wallet Carrot");
#  endif
    USB.begin();
#endif
    cw_link_set_caps(caps);
    cw_link_set_reset_reason((uint8_t)esp_reset_reason());

    xTaskCreatePinnedToCore(worker_task, "cw_worker", CW_WORKER_STACK, NULL, 3, &g_worker, 1);
}

// Вызывается из loop(): приём из Serial и HID
extern "C" void cw_platform_poll(void)
{
    uint8_t chunk[256];
    bool idle = true;
    int avail = Serial.available();
    while (avail > 0) {
        size_t want = (size_t)avail < sizeof(chunk) ? (size_t)avail : sizeof(chunk);
        size_t got = Serial.readBytes(chunk, want);
        if (got == 0) break;
        idle = false;
        g_last_serial_rx = millis() ? millis() : 1;
        cw_link_feed_serial(chunk, got);
        avail = Serial.available();
    }
#if CW_HAVE_HID
    uint8_t rep[CW_LINK_HID_DATA];
    while (ring_pop(rep)) {
        idle = false;
        g_last_hid_rx = millis() ? millis() : 1;
        cw_link_feed_hid(rep);
    }
#endif
    vTaskDelay(pdMS_TO_TICKS(idle ? 5 : 1));
}
