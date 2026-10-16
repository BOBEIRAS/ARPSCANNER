/* Funções partilhadas pela aplicação.
 * Centraliza o tempo monotónico e a ordenação dos dispositivos.
 */
#include <time.h>

#include "util.h"

double util_now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int util_cmp_dev(const void *a, const void *b)
{
    uint32_t x = ((const struct device *)a)->ip;
    uint32_t y = ((const struct device *)b)->ip;
    return (x > y) - (y > x);
}
