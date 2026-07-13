# my-driver

Android ARM64 loadable kernel module — 1:1 reverse-engineered
reconstruction of a real privileged R/W + input-injection + sensor-spoof
+ page-fault-harvest driver. Speaks to userspace over an `ioctl()`
channel obtained via a magic `reboot()` handshake — no `/dev` node. The
module remains registered with the normal kernel module lifecycle; altering
loader-owned module lists or kobjects is deliberately unsupported.

Field-based source against GKI kernel headers — one source tree builds
seven KMI variants via the Docker DDK image. Code uses `task->mm` /
`dev->event_lock` / `pgd_offset(...)` etc. directly; per-kernel struct
layout is the compiler's problem at build time.

## Build matrix

| KMI                | Kernel | Android | CI |
| ------------------ | ------ | ------- | -- |
| `android12-5.10`   | 5.10   | 12      | ✅ |
| `android13-5.10`   | 5.10   | 13      | ✅ |
| `android13-5.15`   | 5.15   | 13      | ✅ |
| `android14-5.15`   | 5.15   | 14      | ✅ |
| `android14-6.1`    | 6.1    | 14      | ✅ |
| `android15-6.6`    | 6.6    | 15      | ✅ (device-tested) |
| `android16-6.12`   | 6.12   | 16      | ✅ |

Runtime device-coverage is currently the `android15-6.6` leg
(NP05J / Vivo / kernel `6.6.56 android15-8 GKI` / KernelSU root). The
other six legs are compile-validated by CI but not yet runtime-tested.

## Quick start — Docker DDK

```bash
cd driver
./build.sh android15-6.6        # or any KMI from the table
# -> driver/my-driver.ko
```

Equivalent one-liner:

```bash
docker run --rm -v "$PWD/driver:/work" -w /work \
    ghcr.io/ylarod/ddk:android15-6.6-20251104 make
```

The default DDK release is `20251104`. It is the first release that builds
`android16-6.12` external modules with normalized KCFI integer type IDs; do
not use `20251016` for that KMI. CI and `driver/build.sh` verify both the
kernel configuration and the compiler command before publishing a 6.12
artifact.

## Quick start — GitHub Actions

Push to a GitHub repo. The included workflow
(`.github/workflows/build.yml`) runs all seven KMI legs in parallel and
uploads `my-driver-<kmi>.ko` as an artifact per leg. A separate Android NDK
job compiles the arm64 client, probe, and benchmark against the same UAPI and
uploads them as `userspace-arm64-v8a`. Trigger manually via
`workflow_dispatch` to pick a specific DDK image release tag.

## Userspace client

Two equivalent build paths — CMake (with NDK toolchain) or direct
`clang++` invocation. **Critical**: link with `-static-libstdc++` or
push `libc++_shared.so` alongside the binary — `/data/local/tmp/` on
device does not have a libc++ runtime.

### CMake

```bash
cd client
cmake -S . -B build \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 \
    -DCMAKE_CXX_FLAGS="-static-libstdc++"
cmake --build build
adb push build/my-driver-client /data/local/tmp/test/
```

### Direct clang++

```bash
$ANDROID_NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android30-clang++ \
    -std=c++17 -O2 -fno-exceptions -fno-rtti -static-libstdc++ \
    -I client/src -I driver/include \
    client/src/Driver.cpp client/src/Main.cpp \
    -o my-driver-client
```

### Usage

The client uses a small RAII C++ class. Global instance `driver` opens
the ioctl fd lazily on first use:

```cpp
#include "Driver.h"

auto pid = driver.findPidByPackage("com.example.game");
if (pid) {
    driver.setTarget(*pid);
    auto base = driver.memory.getModuleBase("libUE4.so");
    if (base) {
        uint32_t magic = driver.memory.read<uint32_t>(*base).value_or(0);
    }
}
driver.touch.down(0, 100, 200);
driver.touch.up(0);
```

`findPidByPackage()` is a driver-side lookup of the process's complete
`argv[0]`, not the 16-byte `task->comm`. Matching is exact: the main process
`com.example.game` and a subprocess such as `com.example.game:remote` are
selected independently by passing their full names.

`driver.open()` issues `syscall(SYS_reboot, 0x123456, 0x123456, 0, &fd)`.
A kprobe inside the driver intercepts the syscall, allocates an
anon-inode fd, and writes it back into the userspace pointer.
**Reachable from `adb shell` uid; bionic seccomp blocks `__NR_reboot`
for Zygote-forked app uids** — if you need to bootstrap from inside an
app, spawn through a privileged helper.

## Test harness (scripts/)

`scripts/src/drv_probe.c` — single-binary correctness harness. Spawns a
helper child with a known mmap pattern + comm, then exercises the core
memory, process, hook, input, and sensor commands against ground truth. The
package-lookup group also
execs a uniquely named child and checks exact matching, empty input, and
bounded NUL handling. The default run records 22 correctness assertions plus
the latency pass; JSON + CSV output; exits non-zero on any failure.

```bash
# Build (same NDK clang++ as the client, +I driver/include):
aarch64-linux-android30-clang -Os -I driver/include \
    scripts/src/drv_probe.c -o drv_probe
adb push drv_probe my-driver-android15-6.6.ko /data/local/tmp/test/
adb shell 'su -c "insmod /data/local/tmp/test/my-driver-android15-6.6.ko"'
adb shell '/data/local/tmp/test/drv_probe --iters=1000 \
    --json=/data/local/tmp/test/results.json \
    --csv=/data/local/tmp/test/timing.csv'
```

`scripts/src/drv_bench.c` — comparative latency benchmark across three
process-memory R/W methods:

| Method | Path |
| --- | --- |
| `procmem` | `open("/proc/<pid>/mem") + pread64` |
| `process_vm_readv` | `syscall(SYS_process_vm_readv, pid, iov, 1, iov, 1, 0)` |
| `driver` | `ioctl(fd, DRV_CMD_READ_MEM_LINEAR, &req)` |

Reads the first N bytes of `--module=libname.so` inside `--pkg=`,
N ∈ {16 B, 256 B, 4 KiB, 64 KiB, 1 MiB}, 1000 iters per
(method, size). Reports median / p95 / p99 / min / max latency +
throughput.

### Current numbers (NP05J / android15-6.6, target: SystemUI/libc.so)

| Size | procmem | process_vm_readv | **driver** |
| --- | --- | --- | --- |
| 16 B  | 1.9 µs | 1.7 µs | **0.9 µs** |
| 256 B | 1.9 µs (133 MB/s) | 1.7 µs (145 MB/s) | **1.0 µs (252 MB/s)** |
| 4 KiB | 2.6 µs (1.5 GB/s) | 2.3 µs (1.7 GB/s) | **1.5 µs (2.6 GB/s)** |
| 64 KiB | 28.6 µs (2.2 GB/s) | 18.4 µs (3.3 GB/s) | **14.8 µs (4.3 GB/s)** |
| **1 MiB** | 437 µs (2.3 GB/s) | **270 µs (3.8 GB/s)** | **220 µs (4.7 GB/s)** |

Driver beats `process_vm_readv` by 1.2–1.9× across all sizes.

`scripts/verify-on-device.sh` — host orchestrator (CMake / NDK build →
adb push → insmod → run → pull results + dmesg slice).

## Layout

```
driver/
  Kbuild               kbuild objs list + ccflags (KCFG_TARGET_PACKAGE etc.)
  Makefile             out-of-tree entry; honours $KERNEL_SRC from DDK image
  build.sh             docker convenience wrapper
  include/driver/
    uapi.h             shared kernel<->userspace ioctl surface
    types.h            internal driver state types
  src/
    lifecycle.c        module initialization (normal module-core lifecycle)
    comm.c             reboot() handshake (kprobe on __arm64_sys_reboot) +
                       dispatch_ioctl router
    memory.c           process pagewalk + read/write_process_memory_linear,
                       _vmap, multi_read_process_memory; in-page-offset-correct;
                       no per-page dcache flush on the read path (the DC CIVAC
                       ladder is kept only on write_ro_memory for SMC scenarios)
    uaccess_target.c   TTBR0-swap copy_*_user wrappers for cross-mm operations
    vfs_hijack.c       /dev/input/event* read interception via fops proxy
    input_synth.c      synthetic MT event injection via kprobe on input_event
    sensor.c           gyro spoofing via libsensorservice.so uprobe
    harvest.c          page-fault address harvest via kprobe on do_mem_abort
                       (NOT inline-hook on do_page_fault — see "Device caveats")
    stealth.c          KGSL/Adreno process concealment (rbtree erase)
    hook_engine.c      KernelPatch-style inline-hook engine (relocate_inst +
                       relo_*). Present but bypassed for harvest on devices
                       with vendor RKP; available for cold-path hooks on
                       unprotected kernels.
    kallsym.c          kallsyms_lookup_name shim via the kprobe-on-symbol trick

client/
  CMakeLists.txt
  src/
    Driver.h           CDriver class + global `driver` instance
    Driver.cpp         single-path reboot() handshake + ioctl wrappers
    Main.cpp           interactive demo (prompt for pid/package, run ops)

scripts/
  CMakeLists.txt           NDK build for drv_probe / drv_bench
  verify-on-device.sh      host orchestrator (build + push + insmod + run + pull)
  src/
    drv_probe.c            correctness harness — 22 core-command assertions
                           with ground-truth verification; JSON + CSV output
    drv_bench.c            latency benchmark vs /proc/<pid>/mem and
                           process_vm_readv; 5 sizes × 1000 iters per method

.github/workflows/build.yml   7-KMI matrix CI; per-leg my-driver-<kmi>.ko artefact
```

## Configurable knobs

```bash
make DRIVER_NAME=my-driver TARGET_PKG='"cent.tmgp.sgame"'
```

| Kbuild variable | default | what it sets |
| --- | --- | --- |
| `DRIVER_NAME` | `my-driver` | output `.ko` filename + `__this_module.name` |
| `TARGET_PKG` | `"cent.tmgp.sgame"` | package the harvest path activates on (quotes required) |
| `ANON_INODE_NAME` | `"[driver]"` | name passed to `anon_inode_getfile` (visible at `/proc/<pid>/fd/<n>`) |
| `REBOOT_MAGIC` | `0x123456u` | sentinel magic the reboot() handshake matches in `inner_regs[0]/[1]` |

## Device caveats

**Module lifecycle.** The module remains visible in `/proc/modules` and
`/sys/module` and intentionally has no unload entry point. Lazy kprobes,
uprobes, and task-work callbacks can retain driver pointers after an ioctl, so
reboot the device before replacing a loaded artifact. Self-unlinking an
external module from module-core lists or deleting its `kobject` is unsafe and
is not supported.

**Vendor RKP / kernel-text integrity protection.** On the NP05J target
(Vivo, kernel `6.6.56 android15-8 GKI`) any modification of
`do_page_fault` text via `aarch64_insn_patch_text` reliably reboots the
kernel within microseconds — even with a correctly cache-coherent +
PXN-cleared trampoline. Vendor hypervisor / RKP-style watchdog.
Workaround: harvest no longer uses an inline hook on `do_page_fault`;
it registers a `kprobe` on `do_mem_abort` instead (same call site, same
signature, KernelSU on the same kernel uses kprobes happily so they're
in the integrity whitelist). The inline-hook engine in
`hook_engine.c` stays compiled in for future cold-path use on
unprotected kernels.

**Handshake reachability.** `reboot()` is admitted to the kernel from
`adb shell` uid on android15-6.6 (the shell SELinux domain doesn't
block it). From a Zygote-forked **app** uid, bionic seccomp blocks
`__NR_reboot` (142) — the SVC never reaches the kprobe. If you need
to open the driver from inside an app, spawn the client from `adb
shell` or via a privileged helper that hasn't installed the bionic
filter.

**On-device workspace.** `/data/local/tmp/test/` — nothing system-wide
is touched. pstore is mounted but ramoops backend isn't configured on
this device; capture kernel logs with `cat /dev/kmsg > file.log &` +
periodic `sync`.

## ioctl surface (driver/include/driver/uapi.h)

Naked-integer cmd values — `dispatch_ioctl` switches on the raw int,
not `_IO/_IOR/_IOW/_IOWR` macros.

| cmd | hex | purpose |
| --- | --- | --- |
| `DRIVER_IOCTL_PING` | `0x9FBF1` | fd-validity probe |
| `DRIVER_IOCTL_HELLO` | `0x1E240` | echo-back protocol probe |
| `DRV_CMD_READ_MEM_LINEAR` | `0x0B` | read target mem via linear-map alias |
| `DRV_CMD_WRITE_MEM_LINEAR` | `0x0C` | write target mem via linear-map alias |
| `DRV_CMD_READ_MEM_VMAP` | `0x0D` | read via vmap (for high-mem / non-direct pages) |
| `DRV_CMD_WRITE_MEM_VMAP` | `0x0E` | write via vmap |
| `DRV_CMD_GET_MODULE_BASE` | `0x0F` | resolve module name → VMA base in target |
| `DRV_CMD_FIND_TASK_BY_COMM` | `0x10` | find pid by `task->comm` |
| `DRV_CMD_READ_VMA_COOKIE` | `0x11` | walk mm_mt by anon_vma_name tag |
| `DRV_CMD_GET_TLS` | `0x12` | target task's saved TPIDR_EL0 |
| `DRV_CMD_HIDE_KGSL` | `0x13` | erase pid from KGSL process rbtrees |
| `DRV_CMD_MULTI_READ` | `0x14` | vectored read across an array of {dst, src, len} descs (req.buf=array, req.extra=count, req.size=1/0 on success/fail) |
| `DRV_CMD_DUMP_VMAS` | `0x15` | serialize file-backed VMAs (start, end) pairs |
| `DRV_CMD_FIND_PID_BY_PACKAGE` | `0x16` | exact process `argv[0]` -> namespace-visible TGID via `drv_find_pid_req` |
| `DRV_CMD_GAME_ASSET_READ_A/_B` | `0xD0` / `0xD4` | drain harvested wz_hero pointers |
| `DRV_CMD_INSTALL_HOOKS` | `0xD1` | arm do_mem_abort + arm64_force_sig_fault kprobes |
| `DRV_CMD_TEAR_DOWN` | `0xD2` | clear wz_hero arenas |
| `DRV_CMD_INSTALL_SIGSEGV_SUPPRESS` | `0xD5` | alias of INSTALL_HOOKS |
| `DRV_CMD_TOUCH_DOWN/UP/MOVE` | `0x12D..0x12F` | synthetic MT events (first call in range lazily arms input kprobes + event pool) |
| `DRV_CMD_SENSOR_BIND` | `0x140` | pid=100: install libsensorservice uprobe; pid=1: toggle gyro_enable; pid=2: set gyro_x/y deltas |

## Reference upstreams

Used for spec verification — preferred over guessing or extrapolating
from kernel docs alone:

- [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch) — the
  inline-hook engine `hook_engine.c` is a port of.
- [fuqiuluo/android-wuwa](https://github.com/fuqiuluo/android-wuwa) —
  closest sibling: R/W, touches, sensor uprobe, KGSL stealth, page-fault
  harvest equivalent.
- [fuqiuluo/ovo](https://github.com/fuqiuluo/ovo) — simpler sibling for
  R/W and touches; documents a `remap_pfn_range`-based zero-copy bulk
  path worth porting if memory-scan throughput becomes critical.
- [tiann/KernelSU](https://github.com/tiann/KernelSU) — comm-channel
  pattern (prctl/reboot magic → anon-inode fd → ioctl).

## License

GPL-2.0-only. See `LICENSE`.
