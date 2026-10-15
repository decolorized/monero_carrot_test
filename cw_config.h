// cw_config.h — MoneroCarrot firmware build settings
#pragma once

#define CW_FW_VERSION   "carrot-1.0"
#define CW_BOARD_NAME   "ESP32-S3"

// Vendor HID (needs Tools > USB Mode = USB-OTG (TinyUSB)). 0 = Serial only.
#define CW_USE_HID      1

// Worker task stack (signing). Large structures live in PSRAM.
#define CW_WORKER_STACK (24 * 1024)
