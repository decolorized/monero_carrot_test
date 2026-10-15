// Замена monero/src/warnings.h для сборки на GCC (ESP32/Xtensa/RISC-V).
// Оригинал содержит только MSVC-специфичные #pragma для подавления
// предупреждений - на нашем тулчейне не нужны, делаем no-op.
#pragma once
#define PUSH_WARNINGS
#define POP_WARNINGS
#define DISABLE_VS_WARNINGS(...)
