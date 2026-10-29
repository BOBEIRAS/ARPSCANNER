#ifndef NETWATCH_OUTPUT_H
#define NETWATCH_OUTPUT_H

#include <stddef.h>

#include "common.h"
#include "net.h"

void output_format_ip(uint32_t ip, char *out, size_t size);
void output_format_mac(const uint8_t *mac, char *out, size_t size);
void output_print_range(uint32_t low, uint32_t high);
void output_print_header(void);
void output_print_self(uint32_t ip, const uint8_t *mac, const char *name,
                       const char *vendor);
void output_print_device(int row, const struct device *device, const char *name,
                         const char *vendor, const char *note);
void output_print_summary(int found, int watch);
void output_log_event(const char *tag, const struct device *device);
void output_set_json(int enabled);
int output_json_enabled(void);
void output_print_json_snapshot(const struct net_state *net,
                                const struct device *devices, int found,
                                int scan_ports);
void output_log_binding_alert(uint32_t ip, uint32_t gateway,
                              const uint8_t *old_mac, const uint8_t *new_mac);
void output_log_port_alert(uint32_t ip, const uint16_t *ports, size_t count);

#endif
