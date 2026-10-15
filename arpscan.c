#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define MAX_DEVS   1024
#define KNOWN_FILE "known_devices.txt"
#define OUI_FILE   "/usr/share/ieee-data/oui.txt"

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
    uint32_t ip; /* host order */
    uint8_t mac[6];
};

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int cmp_dev(const void *a, const void *b)
{
    uint32_t x = ((const struct device *)a)->ip;
    uint32_t y = ((const struct device *)b)->ip;
    return (x > y) - (y > x);
}

/* Fabricante a partir do MAC (ficheiro oficial da IEEE) */
static void vendor(const uint8_t *m, char *out, size_t n)
{
    if (m[0] & 0x02)
    {
        snprintf(out, n, "MAC privado (telemóvel?)");
        return;
    }

    char key[8];
    snprintf(key, sizeof(key), "%02X%02X%02X", m[0], m[1], m[2]);

    snprintf(out, n, "Desconhecido");
    FILE *f = fopen(OUI_FILE, "r");
    if (!f)
        return;

    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        char *p = strstr(line, "(base 16)");
        if (!p || strncmp(line, key, 6) != 0)
            continue;
        p += 9;
        while (*p == ' ' || *p == '\t')
            p++;
        p[strcspn(p, "\r\n")] = '\0';
        snprintf(out, n, "%.39s", p);
        break;
    }
    fclose(f);
}

/* Dispositivos já vistos em scans anteriores */
static uint8_t known[4096][6];
static int n_known = 0;
static int known_file_existed = 0;

static void load_known(void)
{
    FILE *f = fopen(KNOWN_FILE, "r");
    if (!f)
        return;
    known_file_existed = 1;

    char line[128];
    while (fgets(line, sizeof(line), f) && n_known < 4096)
    {
        unsigned int b[6];
        char ip[32];
        if (sscanf(line, "%31s %x:%x:%x:%x:%x:%x", ip,
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 7)
        {
            for (int i = 0; i < 6; i++)
                known[n_known][i] = (uint8_t)b[i];
            n_known++;
        }
    }
    fclose(f);
}

static int is_known(const uint8_t *m)
{
    for (int i = 0; i < n_known; i++)
        if (memcmp(known[i], m, 6) == 0)
            return 1;
    return 0;
}

static void save_known(const char *ip, const uint8_t *m)
{
    FILE *f = fopen(KNOWN_FILE, "a");
    if (!f)
        return;
    fprintf(f, "%s %02x:%02x:%02x:%02x:%02x:%02x\n", ip,
            m[0], m[1], m[2], m[3], m[4], m[5]);
    fclose(f);
}

static void remember_known(const struct device *d)
{
    char ip[INET_ADDRSTRLEN];
    uint32_t n = htonl(d->ip);
    inet_ntop(AF_INET, &n, ip, sizeof(ip));
    save_known(ip, d->mac);
    if (n_known < 4096)
        memcpy(known[n_known++], d->mac, 6);
}

static void log_event(const char *tag, const struct device *d)
{
    char ts[16], ip[INET_ADDRSTRLEN], vend[64];
    time_t t = time(NULL);
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
    uint32_t n = htonl(d->ip);
    inet_ntop(AF_INET, &n, ip, sizeof(ip));
    vendor(d->mac, vend, sizeof(vend));
    printf("[%s] %-7s %-15s %02x:%02x:%02x:%02x:%02x:%02x  %s\n", ts, tag, ip,
           d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4], d->mac[5], vend);
    fflush(stdout);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Uso: %s <interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0)
    {
        fprintf(stderr, "Erro ao abrir raw socket: %s\n", strerror(errno));
        fprintf(stderr, "Dica: corre com sudo.\n");
        return EXIT_FAILURE;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("MAC");
        return EXIT_FAILURE;
    }
    uint8_t mac[6];
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ifindex");
        return EXIT_FAILURE;
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("IP");
        return EXIT_FAILURE;
    }
    uint32_t my_ip_n = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("netmask");
        return EXIT_FAILURE;
    }
    uint32_t mask_n = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;

    uint32_t my_ip = ntohl(my_ip_n);
    uint32_t mask = ntohl(mask_n);
    uint32_t net = my_ip & mask;
    uint32_t bcast = net | ~mask;

    /* Gateway (router) a partir de /proc/net/route */
    uint32_t gw = 0;
    FILE *rf = fopen("/proc/net/route", "r");
    if (rf)
    {
        char line[256], iface[32];
        unsigned long dest, gate;
        if (fgets(line, sizeof(line), rf))
        {
            while (fgets(line, sizeof(line), rf))
            {
                if (sscanf(line, "%31s %lx %lx", iface, &dest, &gate) == 3 &&
                    dest == 0 && strcmp(iface, argv[1]) == 0)
                {
                    gw = ntohl((uint32_t)gate);
                    break;
                }
            }
        }
        fclose(rf);
    }

    load_known();

    struct arp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    memset(pkt.eth_dst, 0xff, 6);
    memcpy(pkt.eth_src, mac, 6);
    pkt.eth_type = htons(ETH_P_ARP);
    pkt.htype = htons(1);
    pkt.ptype = htons(ETH_P_IP);
    pkt.hlen = 6;
    pkt.plen = 4;
    pkt.oper = htons(1);
    memcpy(pkt.sha, mac, 6);
    memcpy(pkt.spa, &my_ip_n, 4);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xff, 6);

    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
    uint32_t net_n = htonl(net + 1), bc_n = htonl(bcast - 1);
    inet_ntop(AF_INET, &net_n, a, sizeof(a));
    inet_ntop(AF_INET, &bc_n, b, sizeof(b));
    printf("\n=== Scanner de rede ===\n");
    printf("A procurar dispositivos entre %s e %s...\n\n", a, b);

       struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t seen_len = (size_t)(bcast - net) + 1;
    uint8_t *seen = calloc(seen_len, 1);
    if (!seen)
    {
        perror("calloc");
        return EXIT_FAILURE;
    }

    static struct device devs[MAX_DEVS];
    static struct device tracked[MAX_DEVS];
    static int miss[MAX_DEVS];
    static int alive[MAX_DEVS];
    int n_tracked = 0;
    int scan_no = 0;
    const int interval = 5; /* segundos entre scans */

    for (;;)
    {
        /* ---- envio ---- */
        for (uint32_t h = net + 1; h < bcast; h++)
        {
            if (h == my_ip)
                continue;
            uint32_t h_n = htonl(h);
            memcpy(pkt.tpa, &h_n, 4);
            if (sendto(sock, &pkt, sizeof(pkt), 0,
                       (struct sockaddr *)&addr, sizeof(addr)) < 0)
            {
                perror("sendto");
                break;
            }
            usleep(200); /* 200 entre pacotes */
        }

        /* ---- receção ---- */
        memset(seen, 0, seen_len);
        int found = 0;
        double deadline = now_sec() + 1.5;

        while (now_sec() < deadline)
        {
            struct arp_packet reply;
            ssize_t len = recvfrom(sock, &reply, sizeof(reply), 0, NULL, NULL);
            if (len < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                perror("recvfrom");
                break;
            }
            if ((size_t)len < sizeof(reply))
                continue;
            if (ntohs(reply.oper) != 2)
                continue;

            uint32_t s_n;
            memcpy(&s_n, reply.spa, 4);
            uint32_t s = ntohl(s_n);
            if (s <= net || s >= bcast)
                continue;
            if (seen[s - net])
                continue;
            seen[s - net] = 1;

            if (found < MAX_DEVS)
            {
                devs[found].ip = s;
                memcpy(devs[found].mac, reply.sha, 6);
                found++;
            }
        }
        qsort(devs, found, sizeof(devs[0]), cmp_dev);

        if (scan_no == 0)
        {
            /* ---- primeiro scan: tabela completa ---- */
            printf(" Nº  Endereço IP       Endereço MAC        Fabricante                               Nota\n");
            printf("---- ----------------- ------------------- ---------------------------------------- ------------------------\n");

            char ipstr[INET_ADDRSTRLEN];
            char vend[64];

            uint32_t me_n = htonl(my_ip);
            inet_ntop(AF_INET, &me_n, ipstr, sizeof(ipstr));
            vendor(mac, vend, sizeof(vend));
            printf(" %-3d %-17s %02x:%02x:%02x:%02x:%02x:%02x   %-40s este computador\n", 1, ipstr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vend);

            for (int i = 0; i < found; i++)
            {
                uint32_t d_n = htonl(devs[i].ip);
                inet_ntop(AF_INET, &d_n, ipstr, sizeof(ipstr));
                vendor(devs[i].mac, vend, sizeof(vend));

                int is_new = known_file_existed && !is_known(devs[i].mac);
                const char *nota = "";
                if (is_new)
                    nota = "!! NOVO DISPOSITIVO !!";
                else if (devs[i].ip == gw)
                    nota = "router (porta de saída)";

                printf(" %-3d %-17s %02x:%02x:%02x:%02x:%02x:%02x   %-40s %s\n", i + 2, ipstr,
                       devs[i].mac[0], devs[i].mac[1], devs[i].mac[2],
                       devs[i].mac[3], devs[i].mac[4], devs[i].mac[5],
                       vend, nota);

                if (!is_known(devs[i].mac))
                    remember_known(&devs[i]);

                tracked[i] = devs[i];
                miss[i] = 0;
            }
            n_tracked = found;

            printf("\n%d dispositivo(s) na rede (contando contigo).\n", found + 1);
            printf("A monitorizar... (Ctrl+C para parar)\n\n");
            fflush(stdout);
        }
        else
        {
            /* ---- scans seguintes: só mudanças ---- */
            memset(alive, 0, sizeof(alive));

            for (int i = 0; i < found; i++)
            {
                int idx = -1;
                for (int j = 0; j < n_tracked; j++)
                    if (memcmp(tracked[j].mac, devs[i].mac, 6) == 0)
                    {
                        idx = j;
                        break;
                    }

                if (idx < 0)
                {
                    int novo = !is_known(devs[i].mac);
                    log_event(novo ? "NOVO!" : "ENTROU", &devs[i]);
                    if (novo)
                        remember_known(&devs[i]);
                    if (n_tracked < MAX_DEVS)
                    {
                        tracked[n_tracked] = devs[i];
                        miss[n_tracked] = 0;
                        alive[n_tracked] = 1;
                        n_tracked++;
                    }
                }
                else
                {
                    if (miss[idx] >= 3)
                        log_event("VOLTOU", &devs[i]);
                    miss[idx] = 0;
                    alive[idx] = 1;
                    tracked[idx].ip = devs[i].ip;
                }
            }

            for (int j = 0; j < n_tracked; j++)
            {
                if (alive[j])
                    continue;
                miss[j]++;
                if (miss[j] == 3)
                    log_event("SAIU", &tracked[j]);
            }
        }

        scan_no++;
        sleep(interval);
    }

    /* nunca chega aqui: o programa corre até ser parado */
    free(seen);
    close(sock);
    return EXIT_SUCCESS;
}