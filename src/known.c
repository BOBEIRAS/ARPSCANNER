/* Guarda os MAC já encontrados e associa IP a MAC.
 * A tabela de associações permite detetar alterações suspeitas sem estado global partilhado.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "known.h"
#include "output.h"

#define KNOWN_FILE "known_devices.txt"

struct binding
{
    uint32_t ip;
    uint8_t mac[6];
    time_t last_alert;
};

static uint8_t known_macs[4096][6];
static int known_count;
static int known_file_exists;
static struct binding bind_tab[MAX_DEVS];
static int binding_count;

void known_load(void)
{
    FILE *f = fopen(KNOWN_FILE, "r");
    if (!f)
        return;
    known_file_exists = 1;

    char line[128];
    while (fgets(line, sizeof(line), f) && known_count < 4096)
    {
        unsigned int b[6];
        char ip[32];
        if (sscanf(line, "%31s %x:%x:%x:%x:%x:%x", ip,
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 7)
        {
            for (int i = 0; i < 6; i++)
                known_macs[known_count][i] = (uint8_t)b[i];
            known_count++;
        }
    }
    fclose(f);
}

int known_is_known(const uint8_t *mac)
{
    for (int i = 0; i < known_count; i++)
        if (memcmp(known_macs[i], mac, 6) == 0)
            return 1;
    return 0;
}

int known_file_was_present(void)
{
    return known_file_exists;
}

static void save_known(const char *ip, const uint8_t *mac)
{
    FILE *f = fopen(KNOWN_FILE, "a");
    if (!f)
        return;
    fprintf(f, "%s %02x:%02x:%02x:%02x:%02x:%02x\n", ip,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    fclose(f);
}

void known_remember(const struct device *device)
{
    char ip[INET_ADDRSTRLEN];
    uint32_t n = htonl(device->ip);
    inet_ntop(AF_INET, &n, ip, sizeof(ip));
    save_known(ip, device->mac);
    if (known_count < 4096)
        memcpy(known_macs[known_count++], device->mac, 6);
}

int known_check_binding(uint32_t ip, const uint8_t *mac, uint32_t gateway)
{
    for (int i = 0; i < binding_count; i++)
    {
        if (bind_tab[i].ip != ip)
            continue;
        if (memcmp(bind_tab[i].mac, mac, 6) == 0)
            return 0;

        time_t now = time(NULL);
        int alert = (now - bind_tab[i].last_alert) >= 10;
        if (alert)
        {
            const uint8_t *old_mac = bind_tab[i].mac;
            output_log_binding_alert(ip, gateway, old_mac, mac);
            bind_tab[i].last_alert = now;
        }
        memcpy(bind_tab[i].mac, mac, 6);
        return alert;
    }
    if (binding_count < MAX_DEVS)
    {
        bind_tab[binding_count].ip = ip;
        memcpy(bind_tab[binding_count].mac, mac, 6);
        bind_tab[binding_count].last_alert = 0;
        binding_count++;
    }
    return 0;
}
