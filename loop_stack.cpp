// Стек loop-задачи Arduino: в loop() только приём USB и разбор кадров.
#include <stddef.h>

size_t getArduinoLoopTaskStackSize(void) {
    return 16 * 1024;
}
