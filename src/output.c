/* Apresenta resultados e alterações do estado da rede.
 * Mantém a formatação num só módulo para tornar a saída consistente.
 */
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

#include "output.h"
#include "oui.h"

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
    printf(" %-3d %-17s %02x:%02x:%02x:%02x:%02x:%02x   %-40s este computador\n",
           1, ipstr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vendor);
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
    printf("[%s] %-7s %-15s %02x:%02x:%02x:%02x:%02x:%02x  %s\n",
           ts, tag, ip, device->mac[0], device->mac[1], device->mac[2],
           device->mac[3], device->mac[4], device->mac[5], vendor);
    fflush(stdout);
}
