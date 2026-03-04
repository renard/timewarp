/*
Copyright © 2026 Sébastien Gross

Created: 2026-03-04
Last changed: 2026-03-04 19:24:21

This program is free software: you can redistribute it and/or
modify it under the terms of the GNU Affero General Public License
as published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public
License along with this program. If not, see
<http://www.gnu.org/licenses/>.
*/



/*
 * timewarp-ctl.c
 *
 * Send a new fake-time value to a running timewarp supervisor.
 *
 * Usage:
 *   timewarp-ctl SOCKET TIME
 *
 * Examples:
 *   timewarp-ctl /tmp/tw.sock '+30d'
 *   timewarp-ctl /tmp/tw.sock '-1h38m24s'
 *   timewarp-ctl /tmp/tw.sock '2023-01-01 00:00:00'
 *   timewarp-ctl /tmp/tw.sock '@0'
 *
 * The socket path must match the --control argument passed to timewarp.
 * The TIME formats are the same as for timewarp itself.
 *
 * Exit code: 0 on success, 1 on error (connection failure or bad time).
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr,
		  "timewarp-ctl (c) Sébastien Gross\n\n"
                "Usage: timewarp-ctl SOCKET TIME\n"
                "\n"
                "Examples:\n"
                "  timewarp-ctl /tmp/tw.sock '+30d'\n"
                "  timewarp-ctl /tmp/tw.sock '-1h38m24s'\n"
                "  timewarp-ctl /tmp/tw.sock '2023-01-01'\n"
                "  timewarp-ctl /tmp/tw.sock '@0'\n");
        return 1;
    }

    const char *sock_path = argv[1];
    const char *time_str  = argv[2];

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    /* Send the time string followed by a newline */
    if (write(fd, time_str, strlen(time_str)) < 0 ||
        write(fd, "\n", 1) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    /* Signal end-of-write so the server knows we are done */
    shutdown(fd, SHUT_WR);

    /* Read and print the server's response (OK or ERROR: ...) */
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    int ret = 0;
    if (n > 0) {
        buf[n] = '\0';
        printf("%s", buf);
        if (strncmp(buf, "ERROR", 5) == 0)
            ret = 1;
    }

    close(fd);
    return ret;
}
