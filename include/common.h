#ifndef NETWATCH_COMMON_H
#define NETWATCH_COMMON_H

#include <stdint.h>

#define MAX_DEVS 1024

struct arp_packet
{
    uint8_t eth_dst[6];
    uint8_t eth_src[6];
    uint16_t eth_type;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed));

struct device
{
    uint32_t ip;
    uint8_t mac[6];
};

#endif
