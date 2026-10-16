#ifndef NETWATCH_PORTS_H
#define NETWATCH_PORTS_H

#include <stddef.h>
#include <stdint.h>

size_t ports_scan_ports(uint32_t ip, uint16_t *open_ports, size_t capacity);
const char *ports_guess_type(const uint16_t *open_ports, size_t count);
void ports_format_list(const uint16_t *open_ports, size_t count,
                       char *out, size_t size);

#endif
