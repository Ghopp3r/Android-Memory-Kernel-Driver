# my-driver

Android ARM64 loadable kernel module — a reverse-engineered reconstruction of a real privileged R/W + input-injection + sensor-spoof + page-fault-harvest driver. Speaks to userspace over an `ioctl()` channel obtained via a magic `reboot()` handshake — no `/dev` node. By default, all supported KMI builds retain the original module-list/sysfs concealment; the vendor-specific KGSL process concealment is compiled out by default.

Field-based source against GKI kernel headers — one source tree builds seven KMI variants via the Docker DDK image. Code uses `task->mm` / `dev->event_lock` / `pgd_offset(...)` directly; per-kernel struct layout is selected by the headers for each build target.

## Build matrix

| KMI | Kernel | Android | Module visibility | CI |
| --- | --- | --- | --- | --- |
| `android12-5.10` | 5.10 | 12 | hidden | ✅ |
| `android13-5.10` | 5.10 | 13 | hidden | ✅ |
| `android13-5.15` | 5.15 | 13 | hidden | ✅ |
| `android14-5.15` | 5.15 | 14 | hidden | ✅ |
| `android14-6.1` | 6.1 | 14 | hidden | ✅ |
| `android15-6.6` | 6.6 | 15 | hidden | ✅ (device-tested) |
| `android16-6.12` | 6.12 | 16 | hidden | ✅ |

Runtime device coverage is currently the `android15-6.6` leg (NP05J / Vivo / kernel `6.6.56 android15-8 GKI` / KernelSU root). The other six legs are compile-validated by CI but not yet runtime-tested.

## Quick start — Docker DDK

```bash
cd driver
./build.sh android15-6.6 # or any KMI from the table
# -> driver/my-driver.ko
HIDE_SELF_MODULE=0 HIDE_KGSL=1 ./build.sh android15-6.6
```

Equivalent one-liner:

```bash
docker run --rm --privileged -v "$PWD/driver:/work" -w /work ghcr.io/ylarod/ddk:android15-6.6-20251104 make
```

The default DDK release is `20251104`. It is the first release that builds `android16-6.12` external modules with normalized KCFI integer type IDs; do not use `20251016` for that KMI. CI and `driver/build.sh` verify both the kernel configuration and the compiler command before publishing a 6.12 artifact.

## Quick start — GitHub Actions

Push to a GitHub repo. The included workflow (`.github/workflows/build.yml`) runs all seven KMI legs in parallel and uploads `my-driver-<kmi>.ko` as an artifact per leg. A separate Android NDK job compiles the arm64 client, probe, and benchmark against the same UAPI and uploads them as `userspace-arm64-v8a`. Trigger manually via `workflow_dispatch` to pick a specific DDK image release tag.

## Userspace client

Two equivalent build paths — CMake with the NDK toolchain or direct `clang++` invocation. **Critical**: link with `-static-libstdc++` or push `libc++_shared.so` alongside the binary because `/data/local/tmp/` does not provide a libc++ runtime.

### CMake

```bash
cd client
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 -DANDROID_STL=c++_static
cmake --build build
adb push build/my-driver-client /data/local/tmp/test/
```

### Direct clang++

```bash
$ANDROID_NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android30-clang++ -std=c++17 -O2 -fno-exceptions -fno-rtti -static-libstdc++ -I client/src -I driver/include client/src/Driver.cpp client/src/Main.cpp -o my-driver-client
```

### Usage

The client uses a small RAII C++ class. Global instance `driver` opens the ioctl fd lazily on first use:

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

`findPidByPackage()` is a driver-side lookup of the process's complete `argv[0]`, not the 16-byte `task->comm`. Matching is exact: the main process `com.example.game` and a subprocess such as `com.example.game:remote` are selected independently by passing their full names.

`driver.open()` issues `syscall(SYS_reboot, 0x123456, 0x123456, 0, &fd)`. The kprobe pre-handler queues task work; when the task resumes, that work creates the anon-inode fd and writes its number to the userspace pointer. **Reachable from `adb shell` uid; bionic seccomp blocks `__NR_reboot` for Zygote-forked app uids** — bootstrap from inside an app through a privileged helper.

## Test harness (scripts/)

`scripts/src/drv_probe.c` is a single-binary correctness harness. It spawns a helper child with a known mmap pattern and comm, then exercises the core memory, process, hook, input, and sensor commands against ground truth. The package lookup group also execs a uniquely named child and checks exact matching, empty input, and bounded NUL handling. The default run records 22 correctness assertions plus the latency pass, writes JSON and CSV output, and exits non-zero on any failure.

```bash
# Build (same NDK clang++ as the client, +I driver/include):
aarch64-linux-android30-clang -Os -I driver/include scripts/src/drv_probe.c -o drv_probe
adb push drv_probe my-driver-android15-6.6.ko /data/local/tmp/test/
adb shell 'su -c "insmod /data/local/tmp/test/my-driver-android15-6.6.ko"'
adb shell '/data/local/tmp/test/drv_probe --iters=1000 --json=/data/local/tmp/test/results.json --csv=/data/local/tmp/test/timing.csv'
```

`scripts/src/drv_bench.c` is a comparative latency benchmark across three process-memory R/W methods:

| Method | Path |
| --- | --- |
| `procmem` | `open("/proc/<pid>/mem") + pread64` |
| `process_vm_readv` | `syscall(SYS_process_vm_readv, pid, iov, 1, iov, 1, 0)` |
| `driver` | `ioctl(fd, DRV_CMD_READ_MEM_LINEAR, &req)` |

Reads the first N bytes of `--module=libname.so` inside `--pkg=`, where N ∈ {16 B, 256 B, 4 KiB, 64 KiB, 1 MiB}, with 1000 iterations per method and size. Reports median / p95 / p99 / min / max latency and throughput.

### Current numbers (NP05J / android15-6.6, target: SystemUI/libc.so)

| Size | procmem | process_vm_readv | **driver** |
| --- | --- | --- | --- |
| 16 B | 1.9 µs | 1.7 µs | **0.9 µs** |
| 256 B | 1.9 µs (133 MB/s) | 1.7 µs (145 MB/s) | **1.0 µs (252 MB/s)** |
| 4 KiB | 2.6 µs (1.5 GB/s) | 2.3 µs (1.7 GB/s) | **1.5 µs (2.6 GB/s)** |
| 64 KiB | 28.6 µs (2.2 GB/s) | 18.4 µs (3.3 GB/s) | **14.8 µs (4.3 GB/s)** |
| **1 MiB** | 437 µs (2.3 GB/s) | **270 µs (3.8 GB/s)** | **220 µs (4.7 GB/s)** |

Driver beats `process_vm_readv` by 1.2–1.9× across all sizes.

`scripts/verify-on-device.sh` is the host orchestrator: CMake / NDK build → adb push → insmod → run → pull results and a dmesg slice.

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
    lifecycle.c        module initialization + compile-time self-concealment
    comm.c             reboot() handshake (kprobe on __arm64_sys_reboot) + dispatch_ioctl router
    memory.c           process pagewalk + read/write_process_memory_linear, _vmap, and multi_read_process_memory; in-page-offset-correct; no per-page dcache flush on reads
    uaccess_target.c   TTBR0-swap copy_*_user wrappers for cross-mm operations
    vfs_hijack.c       /dev/input/event* read interception via fops proxy
    input_synth.c      synthetic MT event injection via kprobe on input_event
    sensor.c           gyro spoofing via libsensorservice.so uprobe
    harvest.c          page-fault address harvest via kprobe on do_mem_abort, not an inline hook on do_page_fault
    stealth.c          KGSL/Adreno process concealment (rbtree erase)
    hook_engine.c      KernelPatch-style inline-hook engine; bypassed for harvest on devices with vendor RKP
    kallsym.c          kallsyms_lookup_name shim via the kprobe-on-symbol trick

client/
  CMakeLists.txt
  src/
    Driver.h           CDriver class + global `driver` instance
    Driver.cpp         single-path reboot() handshake + ioctl wrappers
    SensorResolve.h    libsensorservice symbol resolver for HIDL/AIDL profiles
    Main.cpp           interactive demo (prompt for pid/package, run ops)

scripts/
  CMakeLists.txt           NDK build for drv_probe / drv_bench
  verify-on-device.sh      host orchestrator (build + push + insmod + run + pull)
  src/
    drv_probe.c            correctness harness — 22 core-command assertions with ground-truth verification; JSON + CSV output
    drv_bench.c            latency benchmark vs /proc/<pid>/mem and process_vm_readv; 5 sizes × 1000 iterations per method

.github/workflows/build.yml   7-KMI matrix CI; per-leg my-driver-<kmi>.ko artefact

diagnostics/capture-kmsg.sh   background /dev/kmsg capture helper for device debugging
```

## Configurable knobs

```bash
make DRIVER_NAME=my-driver TARGET_PKG='"cent.tmgp.sgame"' HIDE_SELF_MODULE=1 HIDE_KGSL=0
```

| Kbuild variable | default | what it sets |
| --- | --- | --- |
| `DRIVER_NAME` | `my-driver` | output `.ko` filename + `__this_module.name` |
| `TARGET_PKG` | `"cent.tmgp.sgame"` | `task->comm` value matched by the harvest path, limited to `TASK_COMM_LEN` (quotes required) |
| `REBOOT_MAGIC` | `0x123456u` | sentinel magic the reboot() handshake matches in `inner_regs[0]/[1]` |
| `HIDE_SELF_MODULE` | `1` | compile the LKM module-list/sysfs concealment path (`0` or `1`) |
| `HIDE_KGSL` | `0` | compile the vendor-specific KGSL process concealment path for supported 5.10-6.12 builds (`0` or `1`) |

`ANON_INODE_NAME` is still accepted and forwarded by Kbuild, but the current fd-install path uses the fixed `"[driver]"` literal, so changing that variable has no effect yet.

## Device caveats

**Module lifecycle.** With the default `HIDE_SELF_MODULE=1`, the concealment path removes the module from `/proc/modules` and `/sys/module` after initialization on every supported KMI, including Android 16 / 6.12. It directly mutates loader-owned lists and the module kobject, retaining the same race and maintenance risk as the reconstructed driver. Set `HIDE_SELF_MODULE=0` when a visible module is needed for debugging. Every build intentionally has no unload entry point: lazy kprobes, uprobes, and task-work callbacks can retain driver pointers after an ioctl, so reboot the device before replacing a loaded artifact.

**KGSL concealment.** The vendor-specific KGSL rbtree walker is disabled by default (`HIDE_KGSL=0`) because its offsets are not stable across Qualcomm BSPs. Set `HIDE_KGSL=1` only for a matching Qualcomm device build. The opt-in path selects versioned layouts for the supported 5.10-6.12 KMIs and rejects holder pointers that fail its runtime sanity checks; with the default disabled build, `DRV_CMD_HIDE_KGSL` returns `-EOPNOTSUPP`.

**Vendor RKP / kernel-text integrity protection.** On the NP05J target (Vivo, kernel `6.6.56 android15-8 GKI`) any modification of `do_page_fault` text via `aarch64_insn_patch_text` reliably reboots the kernel within microseconds, even with a correctly cache-coherent and PXN-cleared trampoline. Harvest therefore registers a `kprobe` on `do_mem_abort` instead of inline-hooking `do_page_fault`. The inline-hook engine remains compiled for future cold-path use on unprotected kernels.

**Handshake reachability.** `reboot()` reaches the kernel from the `adb shell` uid on android15-6.6, but bionic seccomp blocks `__NR_reboot` (142) for Zygote-forked app uids before the SVC reaches the kprobe. Bootstrap from inside an app through a privileged helper without that filter.

**On-device workspace.** `/data/local/tmp/test/` is the only device workspace used. pstore is mounted but ramoops is not configured on the tested device; capture kernel logs with `cat /dev/kmsg > file.log &` and periodic `sync`.

## ioctl surface (driver/include/driver/uapi.h)

Naked-integer cmd values — `dispatch_ioctl` switches on the raw int, not `_IO/_IOR/_IOW/_IOWR` macros.

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
| `DRV_CMD_READ_VMA_COOKIE` | `0x11` | exact `anon_vma_name` match returning `vm_start`; available on 5.17+ only when `CONFIG_ANON_VMA_NAME` is enabled |
| `DRV_CMD_GET_TLS` | `0x12` | target task's saved TPIDR_EL0 |
| `DRV_CMD_HIDE_KGSL` | `0x13` | erase pid from KGSL process rbtrees when explicitly built with `HIDE_KGSL=1` |
| `DRV_CMD_MULTI_READ` | `0x14` | vectored read across an array of {dst, src, len} descs (req.buf=array, req.extra=count, req.size=1/0 on success/fail) |
| `DRV_CMD_DUMP_VMAS` | `0x15` | serialize file-backed VMAs (start, end) pairs |
| `DRV_CMD_FIND_PID_BY_PACKAGE` | `0x16` | exact process `argv[0]` -> namespace-visible TGID via `drv_find_pid_req` |
| `DRV_CMD_GAME_ASSET_READ_A/_B` | `0xD0` / `0xD4` | copy the harvested wz_hero buffers to userspace without clearing them |
| `DRV_CMD_INSTALL_HOOKS` | `0xD1` | arm do_mem_abort + arm64_force_sig_fault kprobes |
| `DRV_CMD_TEAR_DOWN` | `0xD2` | clear wz_hero arenas |
| `DRV_CMD_INSTALL_SIGSEGV_SUPPRESS` | `0xD5` | alias of INSTALL_HOOKS |
| `DRV_CMD_TOUCH_DOWN/UP/MOVE` | `0x12D..0x12F` | synthetic MT events (first call in range lazily arms input kprobes + event pool) |
| `DRV_CMD_TOUCH_SLOT_LEGACY` | `0x136` | legacy no-op after the input lazy-init prelude |
| `DRV_CMD_SENSOR_BIND` | `0x140` | `pid=100`: bind the libsensorservice uprobe with an explicit HIDL/AIDL layout; otherwise set gyro X/Y/enable from `addr`/`size`/`extra` |

## Reference upstreams

Used for spec verification — preferred over guessing or extrapolating from kernel docs alone:

- [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch) — source of the ported `hook_engine.c` inline-hook engine.
- [fuqiuluo/android-wuwa](https://github.com/fuqiuluo/android-wuwa) — closest sibling for R/W, touch, sensor uprobe, KGSL concealment, and page-fault harvest behavior.
- [fuqiuluo/ovo](https://github.com/fuqiuluo/ovo) — simpler R/W and touch sibling documenting a `remap_pfn_range`-based zero-copy bulk path.
- [tiann/KernelSU](https://github.com/tiann/KernelSU) — reference for the prctl/reboot magic → anon-inode fd → ioctl communication pattern.

## License

GPL-2.0-only. See [LICENSE](LICENSE), [NOTICE.md](NOTICE.md), and [CONTRIBUTING.md](CONTRIBUTING.md).
