/* Coordena a configuração, os scans e o modo de monitorização.
 * Mantém aqui o estado da execução e delega rede, dados e apresentação.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "common.h"
#include "known.h"
#include "names.h"
#include "net.h"
#include "oui.h"
#include "output.h"
#include "ports.h"
#include "util.h"

struct tracking_state
{
    struct device tracked[MAX_DEVS];
    int miss[MAX_DEVS];
    int alive[MAX_DEVS];
    int count;
};

static void usage(const char *program)
{
    printf("Uso: %s [opções] [alvo]\n\n"
           "  alvo        IP ou intervalo CIDR (ex: 192.168.1.0/24).\n"
           "              Se omitido, usa a rede da interface.\n"
           "  -i iface    interface de rede (por defeito, deteta sozinho)\n"
           "  -w          modo monitor: fica a vigiar e avisa das mudanças\n"
           "  -t seg      tempo de espera por respostas (por defeito 2)\n"
           "  -p          identifica serviços TCP comuns nos dispositivos encontrados\n"
           "  -h          esta ajuda\n",
           program);
}

static void get_port_summary(uint32_t ip, char *out, size_t size)
{
    uint16_t open_ports[18];
    char port_list[80];
    size_t count = ports_scan_ports(ip, open_ports,
                                    sizeof(open_ports) / sizeof(open_ports[0]));
    ports_format_list(open_ports, count, port_list, sizeof(port_list));
    snprintf(out, size, "%s (TCP: %s)", ports_guess_type(open_ports, count), port_list);
}

static void log_port_summary(uint32_t ip)
{
    char address[INET_ADDRSTRLEN], summary[112];
    output_format_ip(ip, address, sizeof(address));
    get_port_summary(ip, summary, sizeof(summary));
    printf("          [PORTAS] %s: %s\n", address, summary);
    fflush(stdout);
}

static int run_scan(struct net_state *net, uint32_t low, uint32_t high,
                    double wait_s, uint8_t *seen, size_t seen_size,
                    struct device *devices)
{
    for (uint32_t host = low; host <= high; host++)
    {
        if (host == net->ip)
            continue;
        if (net_send_arp(net, host) < 0)
        {
            perror("sendto");
            break;
        }
        usleep(200);
    }

    memset(seen, 0, seen_size);
    int found = 0;
    double deadline = util_now_sec() + wait_s;
    while (util_now_sec() < deadline)
    {
        struct arp_packet reply;
        ssize_t length = net_receive_arp(net, &reply);
        if (length < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            perror("recvfrom");
            break;
        }
        if ((size_t)length < sizeof(reply))
            continue;
        if (ntohs(reply.oper) != 2)
            continue;

        uint32_t source_n;
        memcpy(&source_n, reply.spa, 4);
        uint32_t source = ntohl(source_n);
        if (source <= low || source >= high)
            continue;
        known_check_binding(source, reply.sha, net->gateway);
        if (seen[source - low])
            continue;
        seen[source - low] = 1;

        if (found < MAX_DEVS)
        {
            devices[found].ip = source;
            memcpy(devices[found].mac, reply.sha, 6);
            found++;
        }
    }
    qsort(devices, (size_t)found, sizeof(devices[0]), util_cmp_dev);
    return found;
}

static void print_first_scan(const struct net_state *net,
                             const struct device *devices, int found, int watch,
                             int scan_ports,
                             struct tracking_state *tracking)
{
    output_print_header();

    char vendor[64], hostname[64];
    oui_vendor(net->mac, vendor, sizeof(vendor));
    gethostname(hostname, sizeof(hostname));
    output_print_self(net->ip, net->mac, hostname, vendor);

    for (int i = 0; i < found; i++)
    {
        oui_vendor(devices[i].mac, vendor, sizeof(vendor));

        int is_new = known_file_was_present() &&
                     !known_is_known(devices[i].mac);
        const char *note = "";
        if (is_new)
            note = "!! NOVO DISPOSITIVO !!";
        else if (devices[i].ip == net->gateway)
            note = "router (porta de saída)";
        char port_summary[112], full_note[160];
        if (scan_ports)
        {
            get_port_summary(devices[i].ip, port_summary, sizeof(port_summary));
            snprintf(full_note, sizeof(full_note), "%s%s%s",
                     note, note[0] ? " | " : "", port_summary);
            note = full_note;
        }
        char name[64];
        names_device_name(devices[i].ip, devices[i].mac, name, sizeof(name));
        output_print_device(i + 2, &devices[i], name, vendor, note);

        if (!known_is_known(devices[i].mac))
            known_remember(&devices[i]);
        tracking->tracked[i] = devices[i];
        tracking->miss[i] = 0;
    }
    tracking->count = found;
    output_print_summary(found, watch);
}

static void update_after_scan(const struct device *devices, int found,
                              int scan_ports,
                              struct tracking_state *tracking)
{
    memset(tracking->alive, 0, sizeof(tracking->alive));

    for (int i = 0; i < found; i++)
    {
        int index = -1;
        for (int j = 0; j < tracking->count; j++)
            if (memcmp(tracking->tracked[j].mac, devices[i].mac, 6) == 0)
            {
                index = j;
                break;
            }

        if (index < 0)
        {
            int is_new = !known_is_known(devices[i].mac);
            output_log_event(is_new ? "NOVO!" : "ENTROU", &devices[i]);
            if (scan_ports)
                log_port_summary(devices[i].ip);
            if (is_new)
                known_remember(&devices[i]);
            if (tracking->count < MAX_DEVS)
            {
                tracking->tracked[tracking->count] = devices[i];
                tracking->miss[tracking->count] = 0;
                tracking->alive[tracking->count] = 1;
                tracking->count++;
            }
        }
        else
        {
            if (tracking->miss[index] >= 3)
            {
                output_log_event("VOLTOU", &devices[i]);
                if (scan_ports)
                    log_port_summary(devices[i].ip);
            }
            tracking->miss[index] = 0;
            tracking->alive[index] = 1;
            tracking->tracked[index].ip = devices[i].ip;
        }
    }

    for (int j = 0; j < tracking->count; j++)
    {
        if (tracking->alive[j])
            continue;
        tracking->miss[j]++;
        if (tracking->miss[j] == 3)
            output_log_event("SAIU", &tracking->tracked[j]);
    }
}

static void handle_announcement(const struct arp_packet *packet,
                                const struct net_state *net,
                                uint32_t low, uint32_t high,
                                int scan_ports,
                                struct tracking_state *tracking)
{
    uint32_t source_n;
    memcpy(&source_n, packet->spa, 4);
    uint32_t source = ntohl(source_n);
    if (source < low || source > high || source == net->ip)
        return;
    if (memcmp(packet->sha, net->mac, 6) == 0)
        return;

    known_check_binding(source, packet->sha, net->gateway);

    int index = -1;
    for (int j = 0; j < tracking->count; j++)
        if (memcmp(tracking->tracked[j].mac, packet->sha, 6) == 0)
        {
            index = j;
            break;
        }

    if (index < 0)
    {
        struct device device;
        device.ip = source;
        memcpy(device.mac, packet->sha, 6);
        int is_new = !known_is_known(device.mac);
        output_log_event(is_new ? "NOVO!" : "ENTROU", &device);
        if (scan_ports)
            log_port_summary(device.ip);
        if (is_new)
            known_remember(&device);
        if (tracking->count < MAX_DEVS)
        {
            tracking->tracked[tracking->count] = device;
            tracking->miss[tracking->count] = 0;
            tracking->count++;
        }
    }
    else
    {
        if (tracking->miss[index] >= 3)
        {
            output_log_event("VOLTOU", &tracking->tracked[index]);
            if (scan_ports)
                log_port_summary(source);
        }
        tracking->miss[index] = 0;
        tracking->tracked[index].ip = source;
    }
}

static void run_monitor(struct net_state *net, uint32_t low, uint32_t high,
                        double wait_s, uint8_t *seen, size_t seen_size,
                        struct device *devices, int scan_ports,
                        struct tracking_state *tracking)
{
    const int interval = 5;
    for (;;)
    {
        int found = run_scan(net, low, high, wait_s, seen, seen_size, devices);
        update_after_scan(devices, found, scan_ports, tracking);

        double end = util_now_sec() + interval;
        while (util_now_sec() < end)
        {
            struct arp_packet packet;
            ssize_t length = net_receive_arp(net, &packet);
            if (length < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                break;
            }
            if ((size_t)length < sizeof(packet))
                continue;
            handle_announcement(&packet, net, low, high, scan_ports, tracking);
        }
    }
}

int main(int argc, char *argv[])
{
    char ifname[IFNAMSIZ] = "";
    int watch = 0;
    int scan_ports = 0;
    double wait_s = 2.0;
    int option;
    while ((option = getopt(argc, argv, "i:wt:ph")) != -1)
    {
        switch (option)
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
        case 'p':
            scan_ports = 1;
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

    if (ifname[0] == '\0' && !net_default_iface(ifname, sizeof(ifname)))
    {
        fprintf(stderr, "Não encontrei a interface. Usa: %s -i eth0\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct net_state net;
    if (!net_open_socket(ifname, &net))
        return EXIT_FAILURE;

    known_load();
    oui_load();

    uint32_t low = net.network + 1, high = net.broadcast - 1;
    if (target && !net_parse_target(target, &low, &high))
    {
        fprintf(stderr, "Alvo inválido: %s (usa por exemplo 192.168.1.0/24)\n", target);
        return EXIT_FAILURE;
    }
    if (low <= net.network || high >= net.broadcast)
    {
        fprintf(stderr, "Esse alvo está fora da tua rede. O ARP só funciona na rede local.\n");
        return EXIT_FAILURE;
    }

    output_print_range(low, high);
    net_set_receive_timeout(&net);

    size_t seen_size = (size_t)(high - low) + 1;
    uint8_t *seen = calloc(seen_size, 1);
    if (!seen)
    {
        perror("calloc");
        return EXIT_FAILURE;
    }

    static struct device devices[MAX_DEVS];
    struct tracking_state tracking = {0};
    int found = run_scan(&net, low, high, wait_s, seen, seen_size, devices);
    print_first_scan(&net, devices, found, watch, scan_ports, &tracking);
    if (watch)
        run_monitor(&net, low, high, wait_s, seen, seen_size, devices,
                    scan_ports, &tracking);

    free(seen);
    net_close(&net);
    return EXIT_SUCCESS;
}
