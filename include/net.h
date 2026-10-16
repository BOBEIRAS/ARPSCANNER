#ifndef NETWATCH_NET_H
#define NETWATCH_NET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <linux/if_packet.h>

#include "common.h"

struct net_state
{
    int socket_fd;
    int ifindex;
    uint8_t mac[6];
    uint32_t ip;
    uint32_t network;
    uint32_t broadcast;
    uint32_t gateway;
    struct arp_packet request;
    struct sockaddr_ll address;
};

int net_default_iface(char *out, size_t size);
int net_parse_target(const char *target, uint32_t *low, uint32_t *high);
int net_open_socket(const char *ifname, struct net_state *state);
void net_set_receive_timeout(const struct net_state *state);
int net_send_arp(struct net_state *state, uint32_t target_ip);
ssize_t net_receive_arp(const struct net_state *state, struct arp_packet *packet);
void net_close(struct net_state *state);

#endif
