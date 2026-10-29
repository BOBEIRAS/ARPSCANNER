/* Apresenta resultados e alterações do estado da rede.
 * Mantém a formatação num só módulo para tornar a saída consistente.
 */
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

#include "output.h"
#include "names.h"
#include "known.h"
#include "oui.h"
#include "ports.h"

static int json_output;

static void json_string(const char *value)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; p++)
    {
        if (*p == '"' || *p == '\\')
            printf("\\%c", *p);
        else if (*p == '\n')
            printf("\\n");
        else if (*p == '\r')
            printf("\\r");
        else if (*p == '\t')
            printf("\\t");
        else if (*p < 0x20)
            printf("\\u%04x", *p);
        else
            putchar(*p);
    }
    putchar('"');
}

static void json_mac(const uint8_t *mac)
{
    printf("\"%02x:%02x:%02x:%02x:%02x:%02x\"",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void output_set_json(int enabled)
{
    json_output = enabled;
}

int output_json_enabled(void)
{
    return json_output;
}

void output_format_ip(uint32_t ip, char *out, size_t size)
{
    uint32_t network_ip = htonl(ip);
    inet_ntop(AF_INET, &network_ip, out, size);
}

void output_format_mac(const uint8_t *mac, char *out, size_t size)
{
    snprintf(out, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void output_print_range(uint32_t low, uint32_t high)
{
    char first[INET_ADDRSTRLEN], last[INET_ADDRSTRLEN];
    output_format_ip(low, first, sizeof(first));
    output_format_ip(high, last, sizeof(last));
    printf("\n=== Scanner de rede ===\n");
    printf("A procurar dispositivos entre %s e %s...\n\n", first, last);
}

void output_print_header(void)
{
    printf(" Nº  Endereço IP       Endereço MAC        Nome                           Fabricante                               Nota\n");
    printf("---- ----------------- ------------------- ------------------------------ ---------------------------------------- ------------------------\n");
}

void output_print_self(uint32_t ip, const uint8_t *mac, const char *name,
                       const char *vendor)
{
    char ipstr[INET_ADDRSTRLEN];
    output_format_ip(ip, ipstr, sizeof(ipstr));
    printf(" %-3d %-17s %02x:%02x:%02x:%02x:%02x:%02x   %-30.30s %-40s este computador\n",
           1, ipstr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], name, vendor);
}

void output_print_device(int row, const struct device *device, const char *name,
                         const char *vendor, const char *note)
{
    char ipstr[INET_ADDRSTRLEN];
    output_format_ip(device->ip, ipstr, sizeof(ipstr));
    printf(" %-3d %-17s %02x:%02x:%02x:%02x:%02x:%02x   %-30.30s %-40s %s\n",
           row, ipstr, device->mac[0], device->mac[1], device->mac[2],
           device->mac[3], device->mac[4], device->mac[5], name, vendor, note);
}

void output_print_summary(int found, int watch)
{
    printf("\n%d dispositivo(s) na rede (contando contigo).\n", found + 1);
    if (watch)
    {
        printf("A monitorizar... (Ctrl+C para parar)\n\n");
        fflush(stdout);
    }
}

void output_log_event(const char *tag, const struct device *device)
{
    char ts[16], ip[INET_ADDRSTRLEN], vendor[64];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
    output_format_ip(device->ip, ip, sizeof(ip));
    oui_vendor(device->mac, vendor, sizeof(vendor));
    if (json_output)
    {
        printf("{\"type\":\"event\",\"event\":");
        json_string(tag);
        printf(",\"timestamp\":%lld,\"ip\":", (long long)now);
        json_string(ip);
        printf(",\"mac\":");
        json_mac(device->mac);
        printf(",\"vendor\":");
        json_string(vendor);
        puts("}");
        fflush(stdout);
        return;
    }
    printf("[%s] %-7s %-15s %02x:%02x:%02x:%02x:%02x:%02x  %s\n",
           ts, tag, ip, device->mac[0], device->mac[1], device->mac[2],
           device->mac[3], device->mac[4], device->mac[5], vendor);
    fflush(stdout);
}

void output_log_binding_alert(uint32_t ip, uint32_t gateway,
                              const uint8_t *old_mac, const uint8_t *new_mac)
{
    char ipstr[INET_ADDRSTRLEN];
    output_format_ip(ip, ipstr, sizeof(ipstr));
    if (json_output)
    {
        printf("{\"type\":\"alert\",\"alert\":\"arp_mac_changed\",\"timestamp\":%lld,\"ip\":",
               (long long)time(NULL));
        json_string(ipstr);
        printf(",\"severity\":");
        json_string(ip == gateway ? "critical" : "high");
        printf(",\"old_mac\":");
        json_mac(old_mac);
        printf(",\"new_mac\":");
        json_mac(new_mac);
        puts("}");
        fflush(stdout);
        return;
    }

    char ts[16];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
    printf("[%s] %s %s mudou de MAC: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
           ts, ip == gateway ? "!!! CRÍTICO !!!" : "ALERTA", ipstr,
           old_mac[0], old_mac[1], old_mac[2], old_mac[3], old_mac[4], old_mac[5],
           new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5]);
    printf("           %s\n", ip == gateway
                                  ? "Alguém pode estar a fazer-se passar pelo router (ARP spoofing)."
                                  : "Pode ser ARP spoofing, ou o router deu este IP a outro aparelho.");
    fflush(stdout);
}

void output_log_port_alert(uint32_t ip, const uint16_t *ports, size_t count)
{
    char ipstr[INET_ADDRSTRLEN];
    output_format_ip(ip, ipstr, sizeof(ipstr));
    if (!json_output)
        return;

    printf("{\"type\":\"alert\",\"alert\":\"sensitive_port_open\",\"timestamp\":%lld,\"ip\":",
           (long long)time(NULL));
    json_string(ipstr);
    printf(",\"severity\":\"medium\",\"ports\":[");
    for (size_t i = 0; i < count; i++)
        printf("%s%u", i ? "," : "", ports[i]);
    puts("]}");
    fflush(stdout);
}

void output_print_json_snapshot(const struct net_state *net,
                                const struct device *devices, int found,
                                int scan_ports)
{
    char ip[INET_ADDRSTRLEN], vendor[64], name[64];
    output_format_ip(net->ip, ip, sizeof(ip));

    printf("{\"type\":\"snapshot\",\"timestamp\":%lld,\"local_ip\":",
           (long long)time(NULL));
    json_string(ip);
    printf(",\"gateway_ip\":");
    output_format_ip(net->gateway, ip, sizeof(ip));
    json_string(ip);
    printf(",\"devices\":[");
    for (int i = 0; i < found; i++)
    {
        if (i > 0)
            putchar(',');
        output_format_ip(devices[i].ip, ip, sizeof(ip));
        oui_vendor(devices[i].mac, vendor, sizeof(vendor));
        names_device_name(devices[i].ip, devices[i].mac, name, sizeof(name));
        printf("{\"ip\":");
        json_string(ip);
        printf(",\"mac\":");
        json_mac(devices[i].mac);
        printf(",\"name\":");
        json_string(name);
        printf(",\"vendor\":");
        json_string(vendor);
        printf(",\"known\":%s,\"gateway\":%s,\"open_ports\":[",
               known_is_known(devices[i].mac) ? "true" : "false",
               devices[i].ip == net->gateway ? "true" : "false");
        uint16_t open_ports[18];
        size_t count = 0;
        if (scan_ports)
        {
            count = ports_scan_ports(devices[i].ip, open_ports, 18);
            for (size_t j = 0; j < count; j++)
                printf("%s%u", j ? "," : "", open_ports[j]);
        }
        printf("],\"service\":");
        if (scan_ports)
            json_string(ports_guess_type(open_ports, count));
        else
            json_string("not_scanned");
        putchar('}');
    }
    puts("]}");
    fflush(stdout);
}
