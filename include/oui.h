#ifndef NETWATCH_OUI_H
#define NETWATCH_OUI_H

#include <stddef.h>
#include <stdint.h>

void oui_load(void);
void oui_vendor(const uint8_t *mac, char *out, size_t size);

#endif