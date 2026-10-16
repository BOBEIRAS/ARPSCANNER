/* Resolve nomes personalizados, mDNS e DNS inverso para os dispositivos.
 * A ordem de consulta mantém os nomes manuais como primeira opção.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "names.h"

#define NAMES_FILE "names.txt"

static int custom_name(const uint8_t *mac, char *out, size_t size)
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
            int equal = 1;
            for (int i = 0; i < 6; i++)
                if ((uint8_t)b[i] != mac[i])
                    equal = 0;
            if (equal)
            {
                snprintf(out, size, "%s", name);
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    return found;
}

static int read_name(const uint8_t *buffer, int length, int pos, char *out, size_t size)
{
    int end = -1, jumps = 0;
    size_t offset = 0;
    while (pos < length)
    {
        uint8_t c = buffer[pos];
        if (c == 0)
        {
            if (end < 0)
                end = pos + 1;
            out[offset] = '\0';
            return end;
        }
        if ((c & 0xC0) == 0xC0)
        {
            if (pos + 1 >= length || ++jumps > 10)
                return -1;
            if (end < 0)
                end = pos + 2;
            pos = ((c & 0x3F) << 8) | buffer[pos + 1];
            continue;
        }
        pos++;
        if (pos + c > length)
            return -1;
        if (offset && offset < size - 1)
            out[offset++] = '.';
        for (int i = 0; i < c && offset < size - 1; i++)
            out[offset++] = (char)buffer[pos + i];
        pos += c;
    }
    return -1;
}

/* Pergunta diretamente ao dispositivo (UDP 5353) o nome dele. */
static int mdns_name(uint32_t ip_host, char *out, size_t size)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return 0;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 300000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t q[128] = {0};
    int p = 0;
    q[1] = 0x42;
    q[5] = 1;
    p = 12;
    uint8_t octets[4] = {ip_host >> 24, ip_host >> 16, ip_host >> 8, ip_host};
    for (int i = 3; i >= 0; i--)
        p += sprintf((char *)q + p, "%c%d",
                     (char)(octets[i] > 99 ? 3 : octets[i] > 9 ? 2 : 1), octets[i]);
    q[p++] = 7;
    memcpy(q + p, "in-addr", 7);
    p += 7;
    q[p++] = 4;
    memcpy(q + p, "arpa", 4);
    p += 4;
    q[p++] = 0;
    q[p++] = 0;
    q[p++] = 12;
    q[p++] = 0;
    q[p++] = 1;

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
        pos = read_name(r, (int)len, pos, tmp, sizeof(tmp));
        if (pos < 0)
            return 0;
        pos += 4;
    }
    for (int i = 0; i < an; i++)
    {
        pos = read_name(r, (int)len, pos, tmp, sizeof(tmp));
        if (pos < 0 || pos + 10 > len)
            return 0;
        int type = (r[pos] << 8) | r[pos + 1];
        int rdlen = (r[pos + 8] << 8) | r[pos + 9];
        pos += 10;
        if (type == 12 && read_name(r, (int)len, pos, tmp, sizeof(tmp)) >= 0)
        {
            char *suffix = strstr(tmp, ".local");
            if (suffix)
                *suffix = '\0';
            int limit = size > 0 ? (int)(size - 1) : 0;
            snprintf(out, size, "%.*s", limit, tmp);
            return 1;
        }
        pos += rdlen;
    }
    return 0;
}

void names_device_name(uint32_t ip_host, const uint8_t *mac, char *out, size_t size)
{
    if (custom_name(mac, out, size))
        return;

    if (mdns_name(ip_host, out, size))
        return;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip_host);

    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host),
                    NULL, 0, NI_NAMEREQD) == 0)
    {
        char *dot = strchr(host, '.');
        if (dot)
            *dot = '\0';
        int limit = size > 0 ? (int)(size - 1) : 0;
        snprintf(out, size, "%.*s", limit, host);
    }
    else
        snprintf(out, size, "-");
}
