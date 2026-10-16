/* Consulta os fabricantes IEEE associados aos prefixos MAC.
 * A tabela é carregada uma vez para evitar leituras durante a apresentação.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oui.h"

#define OUI_FILE "/usr/share/ieee-data/oui.txt"

struct oui_entry
{
    uint32_t key;
    char name[40];
};

static struct oui_entry *oui_db;
static size_t oui_count;

static int cmp_oui(const void *a, const void *b)
{
    uint32_t x = ((const struct oui_entry *)a)->key;
    uint32_t y = ((const struct oui_entry *)b)->key;
    return (x > y) - (y > x);
}

void oui_load(void)
{
    FILE *f = fopen(OUI_FILE, "r");
    if (!f)
        return;

    size_t capacity = 4096;
    oui_db = malloc(capacity * sizeof(*oui_db));
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
        if (oui_count == capacity)
        {
            struct oui_entry *tmp = realloc(oui_db, capacity * 2 * sizeof(*oui_db));
            if (!tmp)
                break;
            oui_db = tmp;
            capacity *= 2;
        }
        p += 9;
        while (*p == ' ' || *p == '\t')
            p++;
        p[strcspn(p, "\r\n")] = '\0';
        oui_db[oui_count].key = (uint32_t)strtoul(line, NULL, 16);
        snprintf(oui_db[oui_count].name, sizeof(oui_db[oui_count].name), "%.39s", p);
        oui_count++;
    }
    fclose(f);
    qsort(oui_db, oui_count, sizeof(*oui_db), cmp_oui);
}

void oui_vendor(const uint8_t *mac, char *out, size_t size)
{
    if (mac[0] & 0x02)
    {
        snprintf(out, size, "MAC privado (telemóvel?)");
        return;
    }

    struct oui_entry key = {
        .key = ((uint32_t)mac[0] << 16) | (mac[1] << 8) | mac[2]};
    struct oui_entry *entry = oui_db
                                  ? bsearch(&key, oui_db, oui_count, sizeof(*oui_db), cmp_oui)
                                  : NULL;
    snprintf(out, size, "%s", entry ? entry->name : "Desconhecido");
}
