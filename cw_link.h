// cw_link.h — протокол mwlink 3 (frontend/mwlink.py) поверх USB serial:
// COBS + 0x00, заголовок "MWPK"+4 байта, версия 3, CRC32 заголовка и кадра.
//
// Команды: PING, INFO, PUT (auto-kind), GET, STATUS, CLEAR. Устройство
// принимает два вида файлов и обрабатывает их сразу, без подтверждения:
//   "Monero output export"   -> outbox keyimages
//   "Monero unsigned tx set" -> outbox signed_tx
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CW_LINK_PROTO           3
#define CW_LINK_MAX_PAYLOAD     (256u * 1024u)

enum { CW_KIND_OUTPUTS = 0, CW_KIND_KEYIMAGES = 1, CW_KIND_UNSIGNED = 2,
       CW_KIND_SIGNED = 3, CW_KIND_EXPORT = 4, CW_KIND_COUNT = 5 };

enum { CW_LOG_PROGRESS = 0, CW_LOG_ERROR = 1, CW_LOG_INFO = 2, CW_LOG_DEBUG = 3 };

enum { CW_NET_MAINNET = 0, CW_NET_TESTNET = 1, CW_NET_STAGENET = 2 };

#define CW_LINK_HID_DATA   63          // байт данных в HID-отчёте (без report ID)
#define CW_LINK_HID_FIRST  60          // "?##" + 60
#define CW_LINK_HID_CONT   62          // "?"   + 62

enum { CW_TR_EVENT = -1, CW_TR_SERIAL = 0, CW_TR_HID = 1 };

// ---- платформа -------------------------------------------------------------
// Отправить готовое сообщение (заголовок+данные+CRC) в транспорт:
// CW_TR_SERIAL / CW_TR_HID — ответ на запрос, CW_TR_EVENT — во все активные.
void cw_link_send(int transport, const uint8_t *msg, size_t len);
void cw_link_lock(void);                            // мьютекс состояния ящиков
void cw_link_unlock(void);
void cw_link_job_signal(void);                      // разбудить рабочую задачу

// ---- ядро ------------------------------------------------------------------
bool cw_link_init(uint8_t network, const char *fw, const char *board, const char *wallet);
void cw_link_set_reset_reason(uint8_t r);
#define CW_LINK_CAP_SERIAL 0x01
#define CW_LINK_CAP_HID    0x02
void cw_link_set_caps(uint8_t caps);
// пока не готово (ключи грузятся), STATUS = BUSY, PUT отклоняется
void cw_link_set_ready(bool ready);
// байты из serial (COBS + 0x00) и HID-отчёты по 63 байта
void cw_link_feed_serial(const uint8_t *data, size_t n);
void cw_link_feed_hid(const uint8_t rep[CW_LINK_HID_DATA]);
// кадрирование для транспорта
size_t cw_link_serial_frame(const uint8_t *msg, size_t len, uint8_t *out, size_t cap);
size_t cw_link_hid_report_count(size_t len);
void   cw_link_hid_report(const uint8_t *msg, size_t len, size_t idx, uint8_t out[CW_LINK_HID_DATA]);

// Рабочая задача: забрать файл (владение переходит к вызывающему, cw_free)
bool cw_link_job_take(int *kind, uint8_t **data, size_t *len);
// Результат (владение переходит к ядру); data == NULL — отказ
void cw_link_job_done(int out_kind, uint8_t *data, size_t len);
// Два результата сразу (подписанный набор + его _keyImages), атомарно
void cw_link_job_done2(int kind1, uint8_t *data1, size_t len1, int kind2, uint8_t *data2, size_t len2);

// Событие журнала (EVT_LOG) — безопасно из любой задачи
void cw_link_log(int level, const char *text);

// ---- сервис для тестов -----------------------------------------------------
uint32_t cw_crc32(const uint8_t *p, size_t n);

#ifdef __cplusplus
}
#endif
