// MoneroCarrot — Monero cold signer (FCMP++ / Carrot) for the ESP32-S3.
//
// Input: monero-wallet-gui files from the PC program (mwlink, protocol 3):
//          "Monero output export"   v5  -> "Monero key image export" v4/v3
//          "Monero unsigned tx set" v6  -> "Monero signed tx set"    v6 (+ _keyImages)
// Signing happens right away, without confirmation on the device.
//
// Keys: secrets.h (copy from secrets.example.h). Build settings: cw_config.h.
// Board settings and everything else: README.md. In short, Arduino IDE:
// Board "ESP32S3 Dev Module", USB Mode "USB-OTG (TinyUSB)", USB CDC On Boot
// "Enabled", PSRAM "OPI PSRAM" (or QSPI for N8R2), Flash Size 8MB or more,
// Core Debug Level "None". partitions.csv in this folder sets the flash layout.

extern "C" void cw_platform_setup(void);
extern "C" void cw_platform_poll(void);

void setup()
{
    cw_platform_setup();
}

void loop()
{
    cw_platform_poll();
}
