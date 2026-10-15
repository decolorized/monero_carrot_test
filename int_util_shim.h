#pragma once
// Обёртка, чтобы int-util.h собрался на ESP32 (Xtensa GCC).
#ifndef BYTE_ORDER
  #define BYTE_ORDER __BYTE_ORDER__
  #define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
  #define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif
#include "int-util.h"