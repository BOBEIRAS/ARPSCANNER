#ifndef NETWATCH_KNOWN_H
#define NETWATCH_KNOWN_H

#include "common.h"

void known_load(void);
int known_is_known(const uint8_t *mac);
int known_file_was_present(void);
void known_remember(const struct device *device);
int known_check_binding(uint32_t ip, const uint8_t *mac, uint32_t gateway);

#endif
