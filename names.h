#ifndef NETWATCH_NAMES_H
#define NETWATCH_NAMES_H

#include <stddef.h>
#include <stdint.h>

void names_device_name(uint32_t ip_host, const uint8_t *mac, char *out, size_t size);

#endif
