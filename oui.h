#ifndef OUI_H
#define OUI_H
#include <stdint.h>
#include <stddef.h>

void load_oui(void);
void vendor(const uint8_t *m, char *out, size_t n);

#endif