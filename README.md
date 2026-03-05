# timewarp

Run a command with a faked system time — without `LD_PRELOAD`.

```
timewarp '2023-01-01 00:00:00' date
timewarp '@0'                   date
timewarp '+30d'                 curl ...
timewarp '-1h38m24s'            ./my-binary

# with runtime control:
timewarp '-1y' --control /tmp/tw.sock bash
timewarp-ctl /tmp/tw.sock '+30d'
timewarp-ctl /tmp/tw.sock '2024-06-01 12:00:00'
```

## Motivation

The standard tool for time-faking under Linux is
[libfaketime](https://github.com/wolfcw/libfaketime).  It works by
preloading a shared library (`libfaketime.so`) that overrides libc's
`clock_gettime`, `gettimeofday` and `time` wrappers before the program
starts.

This approach has two fundamental limitations:

**1. It requires a matching ELF interpreter.**
`LD_PRELOAD` is processed by the dynamic linker (`ld-linux.so`).  When
a binary ships with a non-standard interpreter path — for example the
relocated `ld-linux-x86-64.so.2` baked in by `patchelf` in a self-contained
tool archive — the system linker is never invoked and `LD_PRELOAD` is silently
ignored.  This is exactly the situation in the `bench-tools` archive that
`timewarp` was built for.

**2. It does not work with statically linked binaries.**
A static binary carries its own libc; there is no dynamic linker to process
`LD_PRELOAD`, so the preloaded library is never loaded.

`timewarp` has neither limitation.  It works at the syscall level, below the
C runtime, and requires no cooperation from the target binary's linker setup.

## How it works

`timewarp` combines two Linux kernel mechanisms:

### 1. Disabling the vDSO (via ptrace)

On x86-64, `clock_gettime(CLOCK_REALTIME)` and `gettimeofday()` are normally
served by the **vDSO** — a small read-only page mapped into every process by
the kernel.  The vDSO reads time data directly from a shared memory region
without issuing a real syscall.  This makes time queries fast, but it also
means they are invisible to `seccomp` filters and `ptrace` syscall
interception.

The C runtime (glibc, musl) discovers the vDSO at startup by reading
`AT_SYSINFO_EHDR` from the ELF auxiliary vector (`auxv`) on the stack.  If
this entry is zero the runtime falls back to regular syscalls for all time
functions.

`timewarp` zeros `AT_SYSINFO_EHDR` in the child's `auxv` at the
**exec-stop** — the instant after `execve` succeeds but before the new
program has executed a single instruction.  The C runtime then initialises
without the vDSO, and every subsequent time call becomes a real syscall.

To locate the entry efficiently, `timewarp` reads the initial stack in a
single `process_vm_readv` call (covering `argc`, `argv`, `envp` and `auxv`
in one shot) and zeros the value with `process_vm_writev`.  For unusually
large environments it falls back to word-by-word `PTRACE_PEEKDATA`.

### 2. Intercepting time syscalls (via seccomp user notification)

`SECCOMP_RET_USER_NOTIF` (Linux ≥ 5.0) allows a supervisor process to
intercept specific syscalls made by a child and respond to them from user
space, without `ptrace` overhead.

Before calling `execvp`, the child installs a BPF filter that redirects
`clock_gettime`, `gettimeofday`, `time`, `clock_nanosleep` and
`timerfd_settime` to a notification queue.  The resulting file descriptor
is handed to the parent via a Unix socket (`SCM_RIGHTS`) before `exec`
replaces the child's address space.  The filter is **inherited across
`fork()` and `exec()`**, so all descendants are automatically covered.

Two interception strategies are used depending on the syscall:

**Read-only time queries** (`clock_gettime`, `gettimeofday`, `time`):

1. The supervisor waits for a notification with `SECCOMP_IOCTL_NOTIF_RECV`.
2. It reads the real time and adds the configured offset.
3. It writes the faked `struct timespec` / `struct timeval` / `time_t`
   directly into the child's memory with `process_vm_writev`.
4. It unblocks the child with a synthetic success response via
   `SECCOMP_IOCTL_NOTIF_SEND`.

The child thread is blocked for the entire duration and receives the faked
value as if it were the normal syscall return.

Only `CLOCK_REALTIME`, `CLOCK_REALTIME_COARSE` and `CLOCK_TAI` are
shifted.  `CLOCK_MONOTONIC` and other interval-measurement clocks are
passed through unmodified — shifting them would break `sleep()`, `poll()`
timeouts, `pthread_cond_timedwait()` and similar primitives.

**Absolute-time operations** (`clock_nanosleep TIMER_ABSTIME`,
`timerfd_settime TFD_TIMER_ABSTIME`):

A program may compute an absolute deadline from the faked clock and then
sleep until that moment:

```c
clock_gettime(CLOCK_REALTIME, &deadline);  // returns faked time
deadline.tv_sec += 5;
clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &deadline, NULL);
// without interception: kernel sleeps until this time in REAL time
// → returns immediately if faked time is in the past, or sleeps too long
```

The supervisor intercepts these calls, subtracts the offset from the
absolute deadline in the tracee's memory (`real_deadline = faked_deadline
− offset`), then resumes the syscall via `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
so the kernel executes it with the corrected value.  Relative operations
and non-wall clocks pass through unchanged.

For `timerfd_settime`, the clock type of the fd is determined at intercept
time by reading `/proc/<pid>/fdinfo/<fd>`, which handles `dup`/`fork`/
`SCM_RIGHTS` correctly without any per-fd tracking.  The periodic
`it_interval` is always relative and requires no adjustment.

### 3. Process-tree tracking (via PTRACE_O_TRACEFORK)

The vDSO disabling step must be repeated at **every** `execve()` in the
process tree, because the kernel writes a fresh `auxv` (including a new
`AT_SYSINFO_EHDR`) for each `execve()`.  Without tree tracking,
grandchildren spawned by a shell (`bash -c date`) would get the vDSO
re-enabled and bypass the seccomp filter.

`timewarp` solves this by **staying attached to the whole process tree**
after the initial exec-stop:

- `PTRACE_O_TRACEFORK` / `PTRACE_O_TRACEVFORK` — auto-attach to every
  forked child and deliver a `PTRACE_EVENT_FORK` stop.
- `PTRACE_O_TRACEEXEC` — deliver an exec-stop for every `execve()` in
  every traced process, so `disable_vdso()` is called again.
- `PTRACE_O_EXITKILL` — kill all tracees if the supervisor exits
  abnormally, preventing orphaned processes.

The supervisor loop polls both `notif_fd` (seccomp) and a `signalfd`
(SIGCHLD) simultaneously, handling both time-call interception and ptrace
tree events in a single thread.

### Full startup sequence

```
timewarp                          target binary / shell
────────────────────────────────────────────────────────
fork()
  │
  ├─[child]  PTRACE_TRACEME
  │           raise(SIGSTOP) ──────────────────────────► stops
  │
  ├─[parent] waitpid(SIGSTOP)
  │           PTRACE_SETOPTIONS(TRACEEXEC)
  │           PTRACE_CONT  ───────────────────────────► resumes
  │
  │          [child]  install seccomp filter
  │                   send notif_fd ──────────────────► (buffered in socket)
  │                   execvp() ───────────────────────► PTRACE_EVENT_EXEC stop
  │
  ├─[parent] recv_fd(notif_fd)
  │           waitpid(PTRACE_EVENT_EXEC)
  │           disable_vdso()   ← POKEDATA AT_SYSINFO_EHDR = 0
  │           PTRACE_SETOPTIONS(TRACEEXEC|TRACEFORK|TRACEVFORK|EXITKILL)
  │           PTRACE_CONT  ───────────────────────────► runs under ptrace
  │
  └─[parent] supervision loop (poll notif_fd + signalfd)
              ◄──── clock_gettime() ──── child thread blocks
              compute fake time
              process_vm_writev() → child memory
              SECCOMP_IOCTL_NOTIF_SEND ───────────────► child thread unblocks
              ...
              ◄──── fork() ────────────────────────── PTRACE_EVENT_FORK stop
              PTRACE_GETEVENTMSG → grandchild pid
              waitpid(grandchild) → initial ptrace-stop
              PTRACE_SETOPTIONS(grandchild, same opts)
              PTRACE_CONT(grandchild)  ───────────────► grandchild runs
              PTRACE_CONT(child)  ────────────────────► child resumes
              ...
              ◄──── execve() ──────────────────────── PTRACE_EVENT_EXEC stop
              disable_vdso(grandchild) ← patch fresh auxv
              PTRACE_CONT(grandchild)  ───────────────► grandchild runs
              ...
              (all processes exit → POLLHUP on notif_fd → loop exits)
```

## Comparison with libfaketime

| | libfaketime | timewarp |
|---|---|---|
| Mechanism | `LD_PRELOAD` | seccomp + ptrace |
| Standard interpreter required | **yes** | no |
| Works with static binaries | **no** | yes |
| Works with custom `patchelf` interpreter | **no** | yes |
| vDSO clock calls intercepted | yes (libc level) | yes (vDSO disabled) |
| Works with shell grandchildren (e.g. `bash -c date`) | yes | yes |
| Requires Linux ≥ 5.0 | no | **yes** |
| No extra privileges needed | yes | yes (same-UID parent) |
| Speed factor / clock drift simulation | yes | no |
| Shared memory file (`-f FILE`) | yes | no |

## Time format

```
timewarp TIME command [args...]
```

| Format | Example | Meaning |
|---|---|---|
| `YYYY-mm-dd HH:MM:SS` | `'2023-06-01 12:00:00'` | Absolute local time |
| `YYYY-mm-dd HH:MM` | `'2023-06-01 12:00'` | Absolute, seconds = 0 |
| `YYYY-mm-dd` | `'2023-06-01'` | Absolute, midnight |
| `@EPOCH` | `'@0'` | Unix timestamp |
| `+NyNdNhNmNs` | `'+1y6h'` | Relative offset forward |
| `-NyNdNhNmNs` | `'-1h38m24s'` | Relative offset backward |

Relative offsets can be compound: `+1y6h` means +365 days and +6 hours.
Units: `y` = 365 days, `d` = day, `h` = hour, `m` = minute, `s` = second.
A bare integer defaults to seconds: `+3600` = `+1h`.

## Runtime control

Start timewarp with `--control PATH` to expose a Unix socket:

```sh
timewarp '-1y' --control /tmp/tw.sock bash
```

From another terminal, send a new time with `timewarp-ctl`:

```sh
timewarp-ctl /tmp/tw.sock '+30d'          # shift forward 30 days from now
timewarp-ctl /tmp/tw.sock '2024-06-01'   # jump to an absolute date
```

The supervisor updates its offset immediately; the next intercepted time
call returns the new value.  The socket file is removed when timewarp exits
normally.

## Building

```sh
make
```

Produces two binaries: `timewarp` and `timewarp-ctl`.

Requires: gcc, Linux kernel headers ≥ 5.0, glibc.

## Limitations

- **x86-64 only** — the vDSO disabling code reads `rsp` from
  `struct user_regs_struct`, which is architecture-specific.  Other
  architectures would need their own register access and may or may not have
  a vDSO for time calls.
- **Linux ≥ 5.0** — `SECCOMP_RET_USER_NOTIF` was introduced in Linux 5.0.
- **Single-threaded supervisor** — the notification loop handles one
  intercepted call at a time.  A child that issues many concurrent time calls
  from multiple threads will see each call serialised through the supervisor.
  In practice this is not measurable for typical bench-tool workloads.
- **clone()-spawned processes** — processes created via `clone()` without
  `SIGCHLD` as the exit signal (i.e. threads) are not auto-attached.
  Threads share the parent's address space so the vDSO is already disabled
  for them; this limitation only affects exotic process-creation patterns
  that do not use `fork()` or `vfork()`.
- **`timerfd_gettime` not intercepted** — `timerfd_gettime()` returns the
  remaining time until expiry in real-time terms.  Programs that use this
  return value to infer elapsed faked time may get confusing results.
  Similarly, the `old_value` output of `timerfd_settime()` reflects the
  previous timer in real time, not faked time.
- **No clock drift / speed factor** — the offset is constant; the clock
  advances at real speed.  libfaketime's `-f` and speed-factor features are
  not implemented.
- **`PR_SET_NO_NEW_PRIVS`** — installing the seccomp filter requires setting
  this flag on the child, which prevents it from gaining privileges via
  setuid or file capabilities.


## Copyright

Copyright (c) Sébastien Gross

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
http://www.gnu.org/licenses
