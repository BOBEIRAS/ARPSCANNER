/* Sonda um conjunto fixo de serviços TCP sem bloquear por ligação.
 * A classificação usa apenas as portas que responderam durante a sondagem.
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ports.h"

struct port_probe
{
    uint16_t port;
    int fd;
};

static const uint16_t common_ports[] = {
    21, 22, 23, 25, 53, 80, 110, 139, 443,
    445, 515, 554, 631, 993, 3306, 3389, 9100, 8080};

size_t ports_scan_ports(uint32_t ip, uint16_t *open_ports, size_t capacity)
{
    struct port_probe probes[sizeof(common_ports) / sizeof(common_ports[0])];
    struct pollfd poll_fds[sizeof(common_ports) / sizeof(common_ports[0])];
    size_t open_count = 0;
    nfds_t pending_count = 0;
    memset(open_ports, 0, capacity * sizeof(*open_ports));

    for (size_t i = 0; i < sizeof(common_ports) / sizeof(common_ports[0]); i++)
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            perror("socket (scan de portas)");
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            perror("fcntl (scan de portas)");
            close(fd);
            continue;
        }

        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons(common_ports[i]);
        address.sin_addr.s_addr = htonl(ip);

        int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
        if (result == 0)
        {
            if (open_count < capacity)
                open_ports[open_count++] = common_ports[i];
            close(fd);
            continue;
        }
        if (errno != EINPROGRESS)
        {
            close(fd);
            continue;
        }

        probes[pending_count].port = common_ports[i];
        probes[pending_count].fd = fd;
        poll_fds[pending_count].fd = fd;
        poll_fds[pending_count].events = POLLOUT;
        poll_fds[pending_count].revents = 0;
        pending_count++;
    }

    int ready = poll(poll_fds, pending_count, 250);
    if (ready > 0)
    {
        for (nfds_t i = 0; i < pending_count; i++)
        {
            if (!(poll_fds[i].revents & (POLLOUT | POLLERR | POLLHUP)))
                continue;

            int error = 0;
            socklen_t error_size = sizeof(error);
            if (getsockopt(probes[i].fd, SOL_SOCKET, SO_ERROR,
                           &error, &error_size) == 0 &&
                error == 0)
            {
                if (open_count < capacity)
                    open_ports[open_count++] = probes[i].port;
            }
        }
    }
    else if (ready < 0)
        perror("poll (scan de portas)");

    for (nfds_t i = 0; i < pending_count; i++)
        close(probes[i].fd);
    return open_count;
}

const char *ports_guess_type(const uint16_t *open_ports, size_t count)
{
    int has_windows = 0, has_web = 0, has_ssh = 0, has_printer = 0;
    for (size_t i = 0; i < count; i++)
    {
        switch (open_ports[i])
        {
        case 139:
        case 445:
        case 3389:
            has_windows = 1;
            break;
        case 80:
        case 443:
        case 8080:
            has_web = 1;
            break;
        case 22:
            has_ssh = 1;
            break;
        case 515:
        case 631:
        case 9100:
            has_printer = 1;
            break;
        default:
            break;
        }
    }

    if (has_printer)
        return "Impressora";
    if (has_windows)
        return "Dispositivo Windows";
    if (has_ssh && !has_web)
        return "Servidor SSH";
    if (has_web)
        return "Servidor web";
    if (has_ssh)
        return "Dispositivo com SSH";
    return "Desconhecido";
}

void ports_format_list(const uint16_t *open_ports, size_t count,
                       char *out, size_t size)
{
    if (size == 0)
        return;
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; i < count; i++)
    {
        int written = snprintf(out + used, size - used, "%s%u",
                               i == 0 ? "" : ",", open_ports[i]);
        if (written < 0 || (size_t)written >= size - used)
            break;
        used += (size_t)written;
    }
    if (count == 0)
        snprintf(out, size, "nenhuma");
}
