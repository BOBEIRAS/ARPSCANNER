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
#include <getopt.h>
#include <netdb.h>

#define MAX_DEVS 1024
#define KNOWN_FILE "known_devices.txt"
#define OUI_FILE "/usr/share/ieee-data/oui.txt"
#define NAMES_FILE "names.txt"

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
struct oui
{
    uint32_t key;
    char name[40];
};
static struct oui *oui_db = NULL;
static size_t oui_n = 0;

static int cmp_oui(const void *a, const void *b)
{
    uint32_t x = ((const struct oui *)a)->key;
    uint32_t y = ((const struct oui *)b)->key;
    return (x > y) - (y > x);
}

static void load_oui(void)
{
    FILE *f = fopen(OUI_FILE, "r");
    if (!f)
        return;
    size_t cap = 4096;
    oui_db = malloc(cap * sizeof(*oui_db));
    if (!oui_db)
    {
        fclose(f);
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        char *p = strstr(line, "(base 16)");
        if (!p)
            continue;
        if (oui_n == cap)
        {
            struct oui *tmp = realloc(oui_db, cap * 2 * sizeof(*oui_db));
            if (!tmp)
                break;
            oui_db = tmp;
            cap *= 2;
        }
        p += 9;
        while (*p == ' ' || *p == '\t')
            p++;
        p[strcspn(p, "\r\n")] = '\0';
        oui_db[oui_n].key = (uint32_t)strtoul(line, NULL, 16);
        snprintf(oui_db[oui_n].name, sizeof(oui_db[oui_n].name), "%.39s", p);
        oui_n++;
    }
    fclose(f);
    qsort(oui_db, oui_n, sizeof(*oui_db), cmp_oui);
}

static void vendor(const uint8_t *m, char *out, size_t n)
{
    if (m[0] & 0x02)
    {
        snprintf(out, n, "MAC privado (telemóvel?)");
        return;
    }
    struct oui k = {.key = ((uint32_t)m[0] << 16) | (m[1] << 8) | m[2]};
    struct oui *r = oui_db ? bsearch(&k, oui_db, oui_n, sizeof(*oui_db), cmp_oui) : NULL;
    snprintf(out, n, "%s", r ? r->name : "Desconhecido");
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

struct binding
{
    uint32_t ip; /* host order */
    uint8_t mac[6];
    time_t last_alert;
};
static struct binding bind_tab[MAX_DEVS];
static int n_bind = 0;

/* Chamada por cada resposta/anúncio ARP visto. Devolve 1 se houve alerta. */
static int check_binding(uint32_t ip, const uint8_t *m, uint32_t gw)
{
    for (int i = 0; i < n_bind; i++)
    {
        if (bind_tab[i].ip != ip)
            continue;
        if (memcmp(bind_tab[i].mac, m, 6) == 0)
            return 0;

        time_t now = time(NULL);
        int alert = (now - bind_tab[i].last_alert) >= 10; /* evita spam */
        if (alert)
        {
            char ts[16], ipstr[INET_ADDRSTRLEN];
            strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
            uint32_t n = htonl(ip);
            inet_ntop(AF_INET, &n, ipstr, sizeof(ipstr));
            const uint8_t *o = bind_tab[i].mac;
            printf("[%s] %s %s mudou de MAC: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
                   ts, ip == gw ? "!!! CRÍTICO !!!" : "ALERTA", ipstr,
                   o[0], o[1], o[2], o[3], o[4], o[5],
                   m[0], m[1], m[2], m[3], m[4], m[5]);
            if (ip == gw)
                printf("           Alguém pode estar a fazer-se passar pelo router (ARP spoofing).\n");
            else
                printf("           Pode ser ARP spoofing, ou o router deu este IP a outro aparelho.\n");
            fflush(stdout);
            bind_tab[i].last_alert = now;
        }
        memcpy(bind_tab[i].mac, m, 6);
        return alert;
    }
    if (n_bind < MAX_DEVS)
    {
        bind_tab[n_bind].ip = ip;
        memcpy(bind_tab[n_bind].mac, m, 6);
        bind_tab[n_bind].last_alert = 0;
        n_bind++;
    }
    return 0;
}

static int default_iface(char *out, size_t n)
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
                snprintf(out, n, "%s", iface);
                ok = 1;
                break;
            }
        }
    }
    fclose(f);
    return ok;
}

static int parse_target(const char *s, uint32_t *lo, uint32_t *hi)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", s);
    int bits = 32;
    char *slash = strchr(buf, '/');
    if (slash)
    {
        *slash = '\0';
        bits = atoi(slash + 1);
    }
    struct in_addr a;
    if (bits < 16 || bits > 32 || inet_pton(AF_INET, buf, &a) != 1)
        return 0;
    uint32_t m = (bits == 32) ? 0xFFFFFFFFu : ~0u << (32 - bits);
    uint32_t first = ntohl(a.s_addr) & m;
    uint32_t last = first | ~m;
    if (bits >= 31)
    {
        *lo = ntohl(a.s_addr);
        *hi = *lo;
    } /* host único */
    else
    {
        *lo = first + 1;
        *hi = last - 1;
    } /* sem rede/broadcast */
    return 1;
}

static void usage(const char *p)
{
    printf("Uso: %s [opções] [alvo]\n\n"
           "  alvo        IP ou intervalo CIDR (ex: 192.168.1.0/24).\n"
           "              Se omitido, usa a rede da interface.\n"
           "  -i iface    interface de rede (por defeito, deteta sozinho)\n"
           "  -w          modo monitor: fica a vigiar e avisa das mudanças\n"
           "  -t seg      tempo de espera por respostas (por defeito 2)\n"
           "  -h          esta ajuda\n",
           p);
}

static int custom_name(const uint8_t *m, char *out, size_t n)
{
    FILE *f = fopen(NAMES_FILE, "r");
    if (!f)
        return 0;
    char line[160];
    int found = 0;
    while (fgets(line, sizeof(line), f))
    {
        unsigned int b[6];
        char name[64];
        if (sscanf(line, "%x:%x:%x:%x:%x:%x %63[^\r\n]",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], name) == 7)
        {
            int eq = 1;
            for (int i = 0; i < 6; i++)
                if ((uint8_t)b[i] != m[i])
                    eq = 0;
            if (eq)
            {
                snprintf(out, n, "%s", name);
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    return found;
}

static int read_name(const uint8_t *b, int len, int pos, char *out, size_t n)
{
    int end = -1, jumps = 0;
    size_t o = 0;
    while (pos < len)
    {
        uint8_t c = b[pos];
        if (c == 0)
        {
            if (end < 0)
                end = pos + 1;
            out[o] = '\0';
            return end;
        }
        if ((c & 0xC0) == 0xC0)
        {
            if (pos + 1 >= len || ++jumps > 10)
                return -1;
            if (end < 0)
                end = pos + 2;
            pos = ((c & 0x3F) << 8) | b[pos + 1];
            continue;
        }
        pos++;
        if (pos + c > len)
            return -1;
        if (o && o < n - 1)
            out[o++] = '.';
        for (int i = 0; i < c && o < n - 1; i++)
            out[o++] = (char)b[pos + i];
        pos += c;
    }
    return -1;
}

/* Pergunta diretamente ao dispositivo (UDP 5353) o nome dele */
static int mdns_name(uint32_t ip_host, char *out, size_t n)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return 0;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 300000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t q[128] = {0};
    int p = 0;
    q[1] = 0x42;           /* id */
    q[5] = 1;              /* 1 pergunta */
    p = 12;
    uint8_t o[4] = {ip_host >> 24, ip_host >> 16, ip_host >> 8, ip_host};
    for (int i = 3; i >= 0; i--)
        p += sprintf((char *)q + p, "%c%d", (char)(o[i] > 99 ? 3 : o[i] > 9 ? 2 : 1), o[i]);
    q[p++] = 7;
    memcpy(q + p, "in-addr", 7);
    p += 7;
    q[p++] = 4;
    memcpy(q + p, "arpa", 4);
    p += 4;
    q[p++] = 0;
    q[p++] = 0; q[p++] = 12; /* tipo PTR */
    q[p++] = 0; q[p++] = 1;  /* classe IN */

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(5353);
    to.sin_addr.s_addr = htonl(ip_host);
    if (sendto(s, q, p, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
    {
        close(s);
        return 0;
    }

    uint8_t r[1500];
    ssize_t len = recv(s, r, sizeof(r), 0);
    close(s);
    if (len < 12)
        return 0;

    int qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7];
    int pos = 12;
    char tmp[256];
    for (int i = 0; i < qd; i++)
    {
        pos = read_name(r, len, pos, tmp, sizeof(tmp));
        if (pos < 0)
            return 0;
        pos += 4;
    }
    for (int i = 0; i < an; i++)
    {
        pos = read_name(r, len, pos, tmp, sizeof(tmp));
        if (pos < 0 || pos + 10 > len)
            return 0;
        int type = (r[pos] << 8) | r[pos + 1];
        int rdlen = (r[pos + 8] << 8) | r[pos + 9];
        pos += 10;
        if (type == 12 && read_name(r, len, pos, tmp, sizeof(tmp)) >= 0)
        {
            char *suf = strstr(tmp, ".local");
            if (suf)
                *suf = '\0';
            snprintf(out, n, "%s", tmp);
            return 1;
        }
        pos += rdlen;
    }
    return 0;
}

static void device_name(uint32_t ip_host, const uint8_t *m, char *out, size_t n)
{
    if (custom_name(m, out, n))
        return;

    if (mdns_name(ip_host, out, n))
        return;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip_host);

    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host),
                    NULL, 0, NI_NAMEREQD) == 0)
    {
        char *dot = strchr(host, '.'); /* corta ".lan", ".home", etc. */
        if (dot)
            *dot = '\0';
        snprintf(out, n, "%s", host);
    }
    else
        snprintf(out, n, "-");
}

int main(int argc, char *argv[])
{
    char ifname[IFNAMSIZ] = "";
    int watch = 0;
    double wait_s = 2.0;
    int opt;
    while ((opt = getopt(argc, argv, "i:wt:h")) != -1)
    {
        switch (opt)
        {
        case 'i':
            snprintf(ifname, sizeof(ifname), "%s", optarg);
            break;
        case 'w':
            watch = 1;
            break;
        case 't':
            wait_s = atof(optarg);
            break;
        case 'h':
            usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    const char *target = (optind < argc) ? argv[optind] : NULL;

    if (ifname[0] == '\0' && !default_iface(ifname, sizeof(ifname)))
    {
        fprintf(stderr, "Não encontrei a interface. Usa: %s -i eth0\n", argv[0]);
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
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

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
                    dest == 0 && strcmp(iface, ifname) == 0)
                {
                    gw = ntohl((uint32_t)gate);
                    break;
                }
            }
        }
        fclose(rf);
    }

    load_known();
    load_oui();

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

    uint32_t lo = net + 1, hi = bcast - 1;
    if (target && !parse_target(target, &lo, &hi))
    {
        fprintf(stderr, "Alvo inválido: %s (usa por exemplo 192.168.1.0/24)\n", target);
        return EXIT_FAILURE;
    }
    if (lo <= net || hi >= bcast)
    {
        fprintf(stderr, "Esse alvo está fora da tua rede. O ARP só funciona na rede local.\n");
        return EXIT_FAILURE;
    }

    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
    uint32_t lo_n = htonl(lo), hi_n = htonl(hi);
    inet_ntop(AF_INET, &lo_n, a, sizeof(a));
    inet_ntop(AF_INET, &hi_n, b, sizeof(b));
    printf("\n=== Scanner de rede ===\n");
    printf("A procurar dispositivos entre %s e %s...\n\n", a, b);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t seen_len = (size_t)(hi - lo) + 1;
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
        for (uint32_t h = lo; h <= hi; h++)
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
        double deadline = now_sec() + wait_s;

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
            if (s <= lo || s >= hi)
                continue;
            check_binding(s, reply.sha, gw);
            if (seen[s - lo])
                continue;
            seen[s - lo] = 1;

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
            printf(" Nº  Endereço IP       Endereço MAC        Nome                           Fabricante                               Nota\n");
            printf("---- ----------------- ------------------- ------------------------------ ---------------------------------------- ------------------------\n");

            char ipstr[INET_ADDRSTRLEN];
            char vend[64];

            uint32_t me_n = htonl(my_ip);
            inet_ntop(AF_INET, &me_n, ipstr, sizeof(ipstr));
            vendor(mac, vend, sizeof(vend));
            char myname[64];
            gethostname(myname, sizeof(myname));
            printf(" %-3d %-17s %02x:%02x:%02x:%02x:%02x:%02x   %-30.30s %-40s este computador\n", 1, ipstr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], myname, vend);
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
                char nm[64];
                device_name(devs[i].ip, devs[i].mac, nm, sizeof(nm));
                printf(" %-3d %-17s %02x:%02x:%02x:%02x:%02x:%02x   %-30.30s %-40s %s\n", i + 2, ipstr,
                       devs[i].mac[0], devs[i].mac[1], devs[i].mac[2],
                       devs[i].mac[3], devs[i].mac[4], devs[i].mac[5],
                       nm, vend, nota);

                if (!is_known(devs[i].mac))
                    remember_known(&devs[i]);

                tracked[i] = devs[i];
                miss[i] = 0;
            }
            n_tracked = found;

            printf("\n%d dispositivo(s) na rede (contando contigo).\n", found + 1);
            if (watch)
            {
                printf("A monitorizar... (Ctrl+C para parar)\n\n");
                fflush(stdout);
            }
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
        if (!watch)
            break;

        /* Em vez de dormir, ouve o ARP durante 'interval' segundos */
        double end = now_sec() + interval;
        while (now_sec() < end)
        {
            struct arp_packet p;
            ssize_t len = recvfrom(sock, &p, sizeof(p), 0, NULL, NULL);
            if (len < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                break;
            }
            if ((size_t)len < sizeof(p))
                continue;

            uint32_t s_n;
            memcpy(&s_n, p.spa, 4);
            uint32_t s = ntohl(s_n);
            if (s < lo || s > hi || s == my_ip)
                continue;
            if (memcmp(p.sha, mac, 6) == 0)
                continue;
                check_binding(s, p.sha, gw);

            int idx = -1;
            for (int j = 0; j < n_tracked; j++)
                if (memcmp(tracked[j].mac, p.sha, 6) == 0)
                {
                    idx = j;
                    break;
                }

            if (idx < 0)
            {
                struct device d;
                d.ip = s;
                memcpy(d.mac, p.sha, 6);
                int novo = !is_known(d.mac);
                log_event(novo ? "NOVO!" : "ENTROU", &d);
                if (novo)
                    remember_known(&d);
                if (n_tracked < MAX_DEVS)
                {
                    tracked[n_tracked] = d;
                    miss[n_tracked] = 0;
                    n_tracked++;
                }
            }
            else
            {
                if (miss[idx] >= 3)
                    log_event("VOLTOU", &tracked[idx]);
                miss[idx] = 0;
                tracked[idx].ip = s;
            }
        }
    }

    /* nunca chega aqui: o programa corre até ser parado */
    free(seen);
    close(sock);
    return EXIT_SUCCESS;
}