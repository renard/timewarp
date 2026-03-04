/*
Copyright © 2026 Sébastien Gross

Created: 2026-03-04
Last changed: 2026-03-04 19:49:02

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
 * timewarp.c
 *
 * Run a command with a faked system time without LD_PRELOAD.
 *
 * WHY NOT LD_PRELOAD
 * ------------------
 * libfaketime works by preloading a shared library that overrides libc's
 * time functions.  This fails when the target binary uses a non-standard
 * ELF interpreter (e.g. a relocated ld-linux from a bench-tools archive)
 * because the system dynamic linker never sees LD_PRELOAD.  It also fails
 * for statically linked binaries.
 *
 * WHY NOT PTRACE ALONE
 * --------------------
 * ptrace can intercept syscalls, but on x86-64 glibc and musl serve
 * clock_gettime(CLOCK_REALTIME) and gettimeofday() from the vDSO - a
 * read-only kernel page mapped into every process.  The vDSO does NOT
 * issue a real syscall; it reads directly from a shared memory page
 * maintained by the kernel.  ptrace only intercepts real syscalls, so
 * it misses all vDSO-served time calls.
 *
 * STRATEGY
 * --------
 * Combining ptrace (to disable the vDSO) with seccomp user-notification
 * (to intercept the resulting real syscalls) solves both problems:
 *
 *   1. PTRACE_TRACEME + raise(SIGSTOP)
 *      Child stops immediately so the parent can configure ptrace options
 *      before the exec.
 *
 *   2. seccomp BPF filter with SECCOMP_RET_USER_NOTIF (Linux >= 5.0)
 *      The child installs a filter that redirects clock_gettime,
 *      gettimeofday and time(2) to a user-space supervisor instead of
 *      executing them normally.  The resulting notification fd is passed
 *      to the parent via a Unix socket (SCM_RIGHTS) before execvp().
 *      The filter is inherited across fork() and exec(), so all processes
 *      in the tree are automatically covered.
 *
 *   3. Zeroing AT_SYSINFO_EHDR via ptrace at every exec-stop
 *      The kernel sets AT_SYSINFO_EHDR in the process's auxiliary vector
 *      (auxv) to tell glibc/musl where the vDSO is mapped.  If this entry
 *      is 0 when the C runtime initialises, it skips the vDSO and falls
 *      back to real syscalls for all time functions.  We patch it with
 *      PTRACE_POKEDATA at the ptrace exec-stop, which fires after execve
 *      succeeds but before a single instruction of the new program runs.
 *      IMPORTANT: the kernel writes a fresh auxv for every execve(), so
 *      we must patch it at EACH exec-stop, not only the first one.
 *
 *   4. Process-tree supervision
 *      Using PTRACE_O_TRACEFORK|TRACEVFORK the parent stays attached to
 *      the entire process tree.  Every time a traced process forks, the
 *      new child is auto-attached.  Every time it calls exec, we get an
 *      exec-stop and call disable_vdso() again.  The same seccomp filter
 *      is inherited and covers all descendants automatically.
 *
 *      A unified supervision loop polls the seccomp notification fd, a
 *      signalfd (SIGCHLD), and an optional control Unix socket.
 *
 * RUNTIME CONTROL
 * ---------------
 * When started with --control PATH, timewarp creates a Unix socket at
 * PATH.  A running timewarp-ctl process connects, sends a new time string
 * (same formats as the initial argument), and receives "OK\n" or an error
 * message.  The supervisor updates its offset immediately; the next
 * intercepted time call will return the new faked time.
 *
 * Requires: Linux >= 5.0 (SECCOMP_RET_USER_NOTIF).
 * Architecture: x86-64 (ptrace register layout in disable_vdso).
 *
 * Usage:
 *   timewarp TIME [--control SOCKET] command [args...]
 *
 *   TIME formats:
 *     'YYYY-mm-dd HH:MM:SS'  absolute local time
 *     '@EPOCH'               unix timestamp
 *     '+/-NyNdNhNmNs'        relative offset from now
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <elf.h>           /* AT_NULL, AT_SYSINFO_EHDR                */
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>  /* signalfd, struct signalfd_siginfo        */
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>       /* process_vm_writev                       */
#include <sys/user.h>      /* struct user_regs_struct                 */
#include <sys/un.h>        /* struct sockaddr_un                      */
#include <sys/wait.h>

#include <poll.h>          /* poll, struct pollfd, POLLIN, POLLHUP    */

#include <linux/filter.h>  /* struct sock_filter, BPF_*               */
#include <linux/seccomp.h> /* SECCOMP_*, struct seccomp_notif*        */

/*
 * ptrace options applied to every process in the supervised tree.
 *
 * PTRACE_O_TRACEEXEC   - get an exec-stop after every execve() so we can
 *                        patch AT_SYSINFO_EHDR in the fresh auxv.
 * PTRACE_O_TRACEFORK   - auto-attach to children created by fork().
 * PTRACE_O_TRACEVFORK  - auto-attach to children created by vfork().
 * PTRACE_O_EXITKILL    - kill all tracees if the supervisor exits
 *                        abnormally (safety net against orphaned processes).
 */
#define PTRACE_TREE_OPTS \
    ((long)(PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | \
            PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL))

/*
 * Parse the fake-time argument
 *
 * Returns 1 on success (*out is set), 0 on error (message printed to
 * errbuf if non-NULL, else to stderr).
 */
static int parse_faketime(const char *s, time_t *out, char *errbuf, size_t errsz)
{
#define PFERR(fmt, ...) do { \
    if (errbuf) snprintf(errbuf, errsz, fmt, ##__VA_ARGS__); \
    else fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
} while (0)

    /* @EPOCH - raw unix timestamp, e.g. "@0" or "@1672531200" */
    if (s[0] == '@') {
        char *end;
        *out = (time_t)strtoll(s + 1, &end, 10);
        if (*end != '\0') {
            PFERR("timewarp: bad epoch: %s", s);
            return 0;
        }
        return 1;
    }

    /* +/-NyNdNhNmNs - relative offset from the current time.
     *
     * Compound expressions are supported: the string is tokenised as a
     * sequence of <integer><unit> pairs.  The leading sign applies to
     * the sum of all pairs.  Examples:
     *   +30d        -> now + 30 days
     *   -1h38m24s   -> now - (1 h + 38 min + 24 s) = now - 5904 s
     *   +1y6h       -> now + 365 days + 6 hours
     *
     * A bare integer without a unit defaults to seconds. */
    if (s[0] == '+' || s[0] == '-') {
        int          sign  = (s[0] == '-') ? -1 : 1;
        const char  *p     = s + 1;
        long         total = 0;

        if (!*p) {
            PFERR("timewarp: empty relative time: %s", s);
            return 0;
        }
        while (*p) {
            char *end;
            errno = 0;
            long  n = strtol(p, &end, 10);
            if (end == p) {
                PFERR("timewarp: expected number in: %s", s);
                return 0;
            }
            if (errno == ERANGE) {
                PFERR("timewarp: number out of range in: %s", s);
                return 0;
            }
            long mult;
            switch (*end) {
            case 'y': mult = 31536000; break;   /* 365 × 86400 s        */
            case 'd': mult = 86400;    break;
            case 'h': mult = 3600;     break;
            case 'm': mult = 60;       break;
            case 's': mult = 1;        break;
            case '\0': mult = 1;       break;
            default:
                PFERR("timewarp: unknown unit '%c' in: %s", *end, s);
                return 0;
            }
            if (n > 0 && n > LONG_MAX / mult) {
                PFERR("timewarp: offset overflow: %s", s);
                return 0;
            }
            total += n * mult;
            p = *end ? end + 1 : end;
        }
        *out = time(NULL) + sign * total;
        return 1;
    }

    /* YYYY-mm-dd [HH:MM[:SS]] - absolute local time */
    struct tm tm = {0};
    const char *fmts[] = {
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        NULL,
    };
    for (int i = 0; fmts[i]; i++) {
        char *ret = strptime(s, fmts[i], &tm);
        if (ret && (*ret == '\0' || *ret == ' ')) {
            tm.tm_isdst = -1;
            time_t t = mktime(&tm);
            if (t == (time_t)-1) {
                PFERR("timewarp: mktime failed for: %s", s);
                return 0;
            }
            *out = t;
            return 1;
        }
    }

    PFERR("timewarp: cannot parse time: %s  "
          "(formats: 'YYYY-mm-dd HH:MM:SS'  '@EPOCH'  '+/-NyNdNhNmNs')", s);
    return 0;

#undef PFERR
}

// Pass a file descriptor over a Unix socket via SCM_RIGHTS
static int send_fd(int sock, int fd)
{
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    char dummy = 0;
    struct iovec  iov  = { &dummy, 1 };
    struct msghdr msg  = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock)
{
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    char dummy;
    struct iovec  iov  = { &dummy, 1 };
    struct msghdr msg  = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    if (recvmsg(sock, &msg, 0) <= 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}


// Install the seccomp BPF filter - called by the child before execvp
static int install_seccomp_filter(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clock_gettime, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_gettimeofday,  2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_time,          1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog = {
        .len    = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }

    int notif_fd = (int)syscall(__NR_seccomp,
                                SECCOMP_SET_MODE_FILTER,
                                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                                &prog);
    if (notif_fd < 0) {
        perror("seccomp(SECCOMP_SET_MODE_FILTER|NEW_LISTENER)");
        return -1;
    }
    return notif_fd;
}

/*
 * Disable the vDSO by zeroing AT_SYSINFO_EHDR in the child's auxv
 *
 * Must be called at EVERY exec-stop across the whole process tree:
 * the kernel re-populates AT_SYSINFO_EHDR in the fresh auxv of each
 * new execve(), re-enabling the vDSO for that image.
 */
static void disable_vdso(pid_t pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace(PTRACE_GETREGS)");
        return;
    }

    unsigned long sp  = (unsigned long)regs.rsp;
    unsigned long ptr;

    errno = 0;
    long argc = ptrace(PTRACE_PEEKDATA, pid, (void *)sp, NULL);
    if (errno) { perror("ptrace(PEEKDATA) argc"); return; }

    ptr = sp + (size_t)(argc + 2) * sizeof(long);

    for (;;) {
        errno = 0;
        long v = ptrace(PTRACE_PEEKDATA, pid, (void *)ptr, NULL);
        if (errno) { perror("ptrace(PEEKDATA) envp"); return; }
        ptr += sizeof(long);
        if (v == 0) break;
    }

    for (;;) {
        errno = 0;
        long type = ptrace(PTRACE_PEEKDATA, pid, (void *)ptr, NULL);
        if (errno) { perror("ptrace(PEEKDATA) auxv type"); return; }
        if (type == AT_NULL) break;
        if (type == AT_SYSINFO_EHDR) {
            if (ptrace(PTRACE_POKEDATA, pid,
                       (void *)(ptr + sizeof(long)), 0L) < 0)
                perror("ptrace(POKEDATA) AT_SYSINFO_EHDR");
            return;
        }
        ptr += 2 * sizeof(long);
    }
}


// Write data directly into the tracee's address space; returns 0 or -1 (errno set)
static int write_to_child(pid_t pid, uint64_t remote_addr,
                           const void *data, size_t len)
{
    if (!remote_addr) return 0;
    struct iovec local  = { (void *)data,        len };
    struct iovec remote = { (void *)remote_addr, len };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0) {
        perror("process_vm_writev");
        return -1;
    }
    return 0;
}


// Handle one intercepted time syscall notification
static void handle_time_notif(int notif_fd, long offset)
{
    struct seccomp_notif      req;
    struct seccomp_notif_resp resp;

    memset(&req, 0, sizeof(req));
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
        if (errno == EINTR || errno == ENOENT || errno == EBADF) return;
        perror("SECCOMP_IOCTL_NOTIF_RECV");
        return;
    }

    memset(&resp, 0, sizeof(resp));
    resp.id = req.id;

    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id) < 0)
        goto send;

    switch (req.data.nr) {

    case __NR_clock_gettime: {
        clockid_t clockid = (clockid_t)(int32_t)req.data.args[0];
        struct timespec ts;
        if (clock_gettime(clockid, &ts) < 0) {
            resp.error = -errno;
        } else {
            /*
             * Only shift wall-time clocks.  Monotonic/CPU clocks measure
             * intervals; applying a wall-time offset to them breaks sleep(),
             * poll() timeouts, pthread_cond_timedwait(), etc.
             */
            switch (clockid) {
            case CLOCK_REALTIME:
            case CLOCK_REALTIME_COARSE:
            case CLOCK_TAI:
                ts.tv_sec += offset;
                break;
            default:
                break;
            }
            if (write_to_child(req.pid, req.data.args[1], &ts, sizeof(ts)) < 0)
                resp.error = -errno;
        }
        break;
    }

    case __NR_gettimeofday: {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += offset;
        struct timeval tv = {
            .tv_sec  = ts.tv_sec,
            .tv_usec = ts.tv_nsec / 1000,
        };
        if (write_to_child(req.pid, req.data.args[0], &tv, sizeof(tv)) < 0)
            resp.error = -errno;
        break;
    }

    case __NR_time: {
        time_t now = time(NULL) + offset;
        resp.val   = (int64_t)now;
        if (write_to_child(req.pid, req.data.args[0], &now, sizeof(now)) < 0)
            resp.error = -errno;
        break;
    }

    default:
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        break;
    }

send:
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        if (errno == ENOENT) return;
        perror("SECCOMP_IOCTL_NOTIF_SEND");
    }
}

/*
 * Handle one connection on the control socket
 *
 * Reads a time string from the client, updates *offset, and replies
 * with "OK\n" or "ERROR: <message>\n".
 */

static void handle_ctl_conn(int ctl_sock, long *offset)
{
    int client = accept4(ctl_sock, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) return;

    /* Read the time string sent by timewarp-ctl (newline-terminated) */
    char buf[256];
    ssize_t n = read(client, buf, sizeof(buf) - 1);
    if (n <= 0) goto done;

    /* Strip trailing whitespace / newlines */
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' ||
                     buf[n-1] == ' '  || buf[n-1] == '\t'))
        n--;
    buf[n] = '\0';
    if (n == 0) goto done;

    /* Parse and update the offset */
    char errbuf[256];
    time_t new_epoch;
    if (!parse_faketime(buf, &new_epoch, errbuf, sizeof(errbuf))) {
        char resp[300];
        int len = snprintf(resp, sizeof(resp), "ERROR: %s\n", errbuf);
        if (write(client, resp, len) < 0) perror("write(control error)");
    } else {
        *offset = (long)new_epoch - (long)time(NULL);
        if (write(client, "OK\n", 3) < 0) perror("write(control ok)");
    }

done:
    close(client);
}

/*
 * Unified supervision loop
 *
 * Polls up to three file descriptors simultaneously:
 *
 *   notif_fd  - seccomp notification fd: time syscall interception.
 *   sfd       - signalfd(SIGCHLD): ptrace event delivery.
 *   ctl_sock  - control Unix socket (>= 0 if --control was given):
 *               timewarp-ctl connects here to change the offset.
 *
 * Exits when POLLHUP fires on notif_fd (all processes in tree exited).
 * Returns the root child's waitpid status.
 */
static int supervision_loop(int notif_fd, int sfd, int ctl_sock,
                             long offset, pid_t root)
{
    int root_wstatus = 0;
    int root_exited  = 0;

    /* We poll 2 or 3 fds depending on whether a control socket was given */
    struct pollfd pfds[3] = {
        { .fd = notif_fd, .events = POLLIN },
        { .fd = sfd,      .events = POLLIN },
        { .fd = ctl_sock, .events = POLLIN },  /* active only when ctl_sock >= 0 */
    };
    int nfds = (ctl_sock >= 0) ? 3 : 2;

    for (;;) {
        int r = poll(pfds, nfds, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        /* Serve one intercepted time syscall */
        if (pfds[0].revents & POLLIN)
            handle_time_notif(notif_fd, offset);

        /*
         * POLLHUP: all tracees have exited.  The guard !(... POLLIN) lets
         * us drain the last notification when both bits fire together;
         * the next poll() iteration returns POLLHUP alone and we break.
         */
        if ((pfds[0].revents & POLLHUP) && !(pfds[0].revents & POLLIN))
            break;

        /*
         * SIGCHLD: harvest all pending ptrace events.
         * Drain one signalfd notification, then loop on waitpid(-1, WNOHANG).
         * __WALL is required to wait for both normal and clone children.
         */
        if (pfds[1].revents & POLLIN) {
            struct signalfd_siginfo ssi;
            read(sfd, &ssi, sizeof(ssi));

            for (;;) {
                int ws;
                pid_t p = waitpid(-1, &ws, WNOHANG | __WALL);
                if (p <= 0) break;

                if (WIFEXITED(ws) || WIFSIGNALED(ws)) {
                    if (p == root) { root_wstatus = ws; root_exited = 1; }
                    continue;
                }

                if (!WIFSTOPPED(ws)) continue;

                int ev = ws >> 8;

                if (ev == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
                    /*
                     * exec-stop: patch AT_SYSINFO_EHDR in the fresh auxv
                     * before the C runtime of the new image initialises.
                     */
                    disable_vdso(p);
                    ptrace(PTRACE_CONT, p, NULL, NULL);

                } else if (ev == (SIGTRAP | (PTRACE_EVENT_FORK  << 8)) ||
                           ev == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
                    /*
                     * fork/vfork-stop: auto-attach to the new child.
                     * The kernel guarantees the child is already in
                     * ptrace-stop (SIGSTOP) before delivering this event.
                     */
                    unsigned long new_pid = 0;
                    ptrace(PTRACE_GETEVENTMSG, p, NULL, &new_pid);
                    if (new_pid > 0) {
                        int nws;
                        waitpid((pid_t)new_pid, &nws, __WALL);
                        ptrace(PTRACE_SETOPTIONS, (pid_t)new_pid, NULL,
                               (void *)PTRACE_TREE_OPTS);
                        ptrace(PTRACE_CONT, (pid_t)new_pid, NULL, NULL);
                    }
                    ptrace(PTRACE_CONT, p, NULL, NULL);

                } else {
                    /* Generic stop: forward the signal */
                    int sig = WSTOPSIG(ws);
                    if (sig == SIGTRAP && (ws >> 8) == 0) sig = 0;
                    ptrace(PTRACE_CONT, p, NULL, (void *)(long)sig);
                }
            }
        }

        /*
         * Control socket: a timewarp-ctl client is requesting an offset
         * change.  We accept the connection, parse the new time, and
         * update offset directly (single-threaded, no locking needed).
         */
        if (nfds == 3 && (pfds[2].revents & POLLIN))
            handle_ctl_conn(ctl_sock, &offset);
    }

    /* Reap root's zombie if not yet collected */
    if (!root_exited) {
        int ws;
        while (waitpid(root, &ws, __WALL) < 0 && errno == EINTR) {}
        root_wstatus = ws;
    }

    /* Detach any remaining ptrace-stopped processes */
    for (;;) {
        int ws;
        pid_t p = waitpid(-1, &ws, WNOHANG | __WALL);
        if (p <= 0) break;
        if (WIFSTOPPED(ws))
            ptrace(PTRACE_DETACH, p, NULL, NULL);
    }

    return root_wstatus;
}

// Main
static void usage()
{
    fprintf(stderr,
	     "timewarp (c) Sébastien Gross\n"
            "Usage: timewarp TIME [--control SOCKET] command [args...]\n"
            "\n"
            "TIME formats:\n"
            "  'YYYY-mm-dd HH:MM:SS'   absolute local time\n"
            "  '@EPOCH'                unix timestamp\n"
            "  '+NyNdNhNmNs'           relative offset (compound ok)\n"
            "  '-NyNdNhNmNs'           units: y d h m s\n"
            "\n"
            "Options:\n"
            "  --control|-c SOCKET     create a Unix socket for runtime\n"
            "                          time changes via timewarp-ctl\n"
            "\n"
            "Examples:\n"
            "  timewarp '2023-01-01 00:00:00' date\n"
            "  timewarp '-1y' --control /tmp/tw.sock bash\n"
            "  timewarp-ctl /tmp/tw.sock '+30d'\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    if (argc < 3) usage();

    /* Parse optional --control SOCKET between TIME and command */
    char *ctl_path = NULL;
    int   cmd_idx  = 2;
    if (argc > 3 && ((strcmp(argv[2], "--control") == 0)
			|| (strcmp(argv[2], "-c") == 0))) {
        ctl_path = argv[3];
        cmd_idx  = 4;
    }
    if (cmd_idx >= argc) usage();

    /*
     * Block SIGCHLD before forking so signalfd reliably captures it.
     * The child restores the default mask before exec.
     */
    sigset_t chldset;
    sigemptyset(&chldset);
    sigaddset(&chldset, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &chldset, NULL) < 0) {
        perror("sigprocmask");
        return 1;
    }

    /*
     * signalfd: delivers SIGCHLD as readable data, compatible with poll().
     * SFD_NONBLOCK: reads in supervision_loop don't block.
     * SFD_CLOEXEC:  closed automatically in the child after exec.
     */
    int sfd = signalfd(-1, &chldset, SFD_CLOEXEC | SFD_NONBLOCK);
    if (sfd < 0) { perror("signalfd"); return 1; }

    /* Declare cleanup-tracked resources early so goto cleanup is always safe */
    int      ctl_sock = -1;
    int      notif_fd = -1;
    int      sv[2]    = { -1, -1 };

    /* Parse the fake time and compute the signed offset from now */
    time_t fake_epoch;
    if (!parse_faketime(argv[1], &fake_epoch, NULL, 0)) goto cleanup;
    long offset = (long)fake_epoch - (long)time(NULL);

    /*
     * Control socket: create, bind and listen before fork so the parent
     * holds the only reference.  SOCK_CLOEXEC ensures the child does not
     * inherit it across exec.
     */
    if (ctl_path) {
        ctl_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (ctl_sock < 0) { perror("socket(control)"); goto cleanup; }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, ctl_path, sizeof(addr.sun_path) - 1);

        /* Remove stale socket from a previous (crashed) run */
        unlink(ctl_path);

        if (bind(ctl_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind(control)"); goto cleanup;
        }
        if (listen(ctl_sock, 8) < 0) {
            perror("listen(control)"); goto cleanup;
        }
    }

    /*
     * Socketpair to transfer the seccomp notification fd from child to
     * parent via SCM_RIGHTS before execvp() replaces the child's image.
     */
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
        perror("socketpair");
        goto cleanup;
    }

    pid_t child = fork();
    if (child < 0) { perror("fork"); goto cleanup; }

    if (child == 0) {
        // CHILD SIDE
        close(sv[0]);
        close(sfd);
        if (ctl_sock >= 0) close(ctl_sock);

        /* Restore default signal mask before exec */
        sigprocmask(SIG_UNBLOCK, &chldset, NULL);

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(1);
        }
        raise(SIGSTOP);

        int nfd = install_seccomp_filter();
        if (nfd < 0) _exit(1);

        if (send_fd(sv[1], nfd) < 0) {
            perror("send_fd(notif_fd)");
            _exit(1);
        }
        close(nfd);
        close(sv[1]);

        execvp(argv[cmd_idx], argv + cmd_idx);
        perror(argv[cmd_idx]);
        _exit(127);
    }

     // PARENT SIDE
    close(sv[1]); sv[1] = -1;

    int wstatus;
    if (waitpid(child, &wstatus, 0) < 0) { perror("waitpid"); goto cleanup; }
    if (!WIFSTOPPED(wstatus)) {
        fprintf(stderr, "timewarp: unexpected initial child state\n");
        goto cleanup;
    }

    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
               (void *)(unsigned long)PTRACE_O_TRACEEXEC) < 0) {
        perror("ptrace(PTRACE_SETOPTIONS)");
        goto cleanup;
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
        perror("ptrace(PTRACE_CONT)");
        goto cleanup;
    }

    notif_fd = recv_fd(sv[0]);
    if (notif_fd < 0) {
        fprintf(stderr, "timewarp: failed to receive notification fd\n");
        goto cleanup;
    }
    close(sv[0]); sv[0] = -1;

    if (waitpid(child, &wstatus, 0) < 0) { perror("waitpid"); goto cleanup; }
    if (WIFSTOPPED(wstatus) &&
        (wstatus >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
        disable_vdso(child);
    }

    /* Upgrade to full tree-tracking options, then resume under ptrace */
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)PTRACE_TREE_OPTS) < 0) {
        perror("ptrace(PTRACE_SETOPTIONS tree)");
        goto cleanup;
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
        perror("ptrace(PTRACE_CONT)");
        goto cleanup;
    }

    int final_wstatus = supervision_loop(notif_fd, sfd, ctl_sock, offset, child);
    close(notif_fd); notif_fd = -1;
    close(sfd);      sfd = -1;
    if (ctl_sock >= 0) {
        close(ctl_sock); ctl_sock = -1;
        unlink(ctl_path);
        ctl_path = NULL;
    }

    if (WIFEXITED(final_wstatus))   return WEXITSTATUS(final_wstatus);
    if (WIFSIGNALED(final_wstatus)) return 128 + WTERMSIG(final_wstatus);
    return 1;

cleanup:
    if (sfd >= 0)      close(sfd);
    if (sv[0] >= 0)    close(sv[0]);
    if (sv[1] >= 0)    close(sv[1]);
    if (notif_fd >= 0) close(notif_fd);
    if (ctl_sock >= 0) {
        close(ctl_sock);
        if (ctl_path) unlink(ctl_path);
    }
    return 1;
}
