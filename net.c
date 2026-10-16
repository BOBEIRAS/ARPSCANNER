/* Gere a interface de rede e o transporte ARP em Linux.
 * Os endereços são mantidos em ordem de host para simplificar os limites do scan.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>

#include "net.h"

int net_default_iface(char *out, size_t size)
{
    FILE *f = fopen("/proc/net/route", "r");
    if (!f)
        return 0;
    char line[256], iface[32];
    unsigned long dest;
    int ok = 0;
    if (fgets(line, sizeof(line), f))
    {
        while (fgets(line, sizeof(line), f))
        {
            if (sscanf(line, "%31s %lx", iface, &dest) == 2 && dest == 0)
            {
                if (size > 0)
                    snprintf(out, size, "%.*s", (int)(size - 1), iface);
                ok = 1;
                break;
            }
        }
    }
    fclose(f);
    return ok;
}

int net_parse_target(const char *target, uint32_t *low, uint32_t *high)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", target);
    int bits = 32;
    char *slash = strchr(buf, '/');
    if (slash)
    {
        *slash = '\0';
        bits = atoi(slash + 1);
    }
    struct in_addr address;
    if (bits < 16 || bits > 32 || inet_pton(AF_INET, buf, &address) != 1)
        return 0;
    uint32_t mask = (bits == 32) ? 0xFFFFFFFFu : ~0u << (32 - bits);
    uint32_t first = ntohl(address.s_addr) & mask;
    uint32_t last = first | ~mask;
    if (bits >= 31)
    {
        *low = ntohl(address.s_addr);
        *high = *low;
    }
    else
    {
        *low = first + 1;
        *high = last - 1;
    }
    return 1;
}

static uint32_t get_gateway(const char *ifname)
{
    uint32_t gateway = 0;
    FILE *f = fopen("/proc/net/route", "r");
    if (f)
    {
        char line[256], iface[32];
        unsigned long dest, gate;
        if (fgets(line, sizeof(line), f))
        {
            while (fgets(line, sizeof(line), f))
            {
                if (sscanf(line, "%31s %lx %lx", iface, &dest, &gate) == 3 &&
                    dest == 0 && strcmp(iface, ifname) == 0)
                {
                    gateway = ntohl((uint32_t)gate);
                    break;
                }
            }
        }
        fclose(f);
    }
    return gateway;
}

int net_open_socket(const char *ifname, struct net_state *state)
{
    memset(state, 0, sizeof(*state));
    state->socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (state->socket_fd < 0)
    {
        fprintf(stderr, "Erro ao abrir raw socket: %s\n", strerror(errno));
        fprintf(stderr, "Dica: corre com sudo.\n");
        return 0;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    size_t name_len = strnlen(ifname, IFNAMSIZ - 1);
    memcpy(ifr.ifr_name, ifname, name_len);

    if (ioctl(state->socket_fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("MAC");
        return 0;
    }
    memcpy(state->mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(state->socket_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ifindex");
        return 0;
    }
    state->ifindex = ifr.ifr_ifindex;

    if (ioctl(state->socket_fd, SIOCGIFADDR, &ifr) < 0)
    {
        perror("IP");
        return 0;
    }
    uint32_t ip_n = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    if (ioctl(state->socket_fd, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("netmask");
        return 0;
    }
    uint32_t mask_n = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;

    state->ip = ntohl(ip_n);
    uint32_t mask = ntohl(mask_n);
    state->network = state->ip & mask;
    state->broadcast = state->network | ~mask;
    state->gateway = get_gateway(ifname);

    memset(&state->request, 0, sizeof(state->request));
    memset(state->request.eth_dst, 0xff, 6);
    memcpy(state->request.eth_src, state->mac, 6);
    state->request.eth_type = htons(ETH_P_ARP);
    state->request.htype = htons(1);
    state->request.ptype = htons(ETH_P_IP);
    state->request.hlen = 6;
    state->request.plen = 4;
    state->request.oper = htons(1);
    memcpy(state->request.sha, state->mac, 6);
    memcpy(state->request.spa, &ip_n, 4);

    memset(&state->address, 0, sizeof(state->address));
    state->address.sll_family = AF_PACKET;
    state->address.sll_ifindex = state->ifindex;
    state->address.sll_halen = 6;
    memset(state->address.sll_addr, 0xff, 6);
    return 1;
}

void net_set_receive_timeout(const struct net_state *state)
{
    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(state->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int net_send_arp(struct net_state *state, uint32_t target_ip)
{
    uint32_t target_n = htonl(target_ip);
    memcpy(state->request.tpa, &target_n, 4);
    return (int)sendto(state->socket_fd, &state->request, sizeof(state->request), 0,
                       (struct sockaddr *)&state->address, sizeof(state->address));
}

ssize_t net_receive_arp(const struct net_state *state, struct arp_packet *packet)
{
    return recvfrom(state->socket_fd, packet, sizeof(*packet), 0, NULL, NULL);
}

void net_close(struct net_state *state)
{
    close(state->socket_fd);
}
