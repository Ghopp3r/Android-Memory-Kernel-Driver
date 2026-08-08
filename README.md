# my-driver

Android ARM64 loadable kernel module: process memory R/W, HW breakpoints, PTE inline hooks, touch injection, sensor spoofing, page-fault harvest, plus compile-time concealment layers for the LKM itself and for the client PID. The userspace fd is created through a magic `reboot()` handshake; no `/dev` node.

Defaults hide the LKM (`HIDE_SELF_MODULE=1`, `HIDE_VMAP=1`) and arm the PID-hiding path (`HIDE_TASK=1`). KGSL concealment is opt-in via a strength scale (`HIDE_KGSL_STRENGTH=0`).

## Build matrix

GitHub Actions builds the module against seven KMIs plus the arm64-v8a userspace client:

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`

Runtime coverage today is `android15-6.6` (NP05J / Android 15 / kernel 6.6.56). The other legs are compile-validated.

## Build

Kernel code builds inside the matching `ghcr.io/ylarod/ddk:<kmi>-<release>` image (default release `20251104`, required by `android16-6.12` KCFI):

```bash
cd driver
make                                             # defaults
make HIDE_SELF_MODULE=1 HIDE_VMAP=1 HIDE_TASK=1  # everything on except KGSL
make HIDE_KGSL_STRENGTH=3                        # KGSL retro + proactive
```

## Userspace client

```bash
cmake -S client -B out/client -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
cmake --build out/client
```

The client opens the fd lazily. `findPidByPackage()` matches the complete `argv[0]`; after `setTarget(pid)` the standard APIs live under `driver.memory`, `driver.touch`, `driver.gyro`, `driver.hwbp`, `driver.pteHook`, and `driver.hide`.

## Concealment layers

The driver has four independent hide surfaces. Each is compile-gated so a build only pays for what it enables.

### `HIDE_SELF_MODULE` (default 1)

Unlinks the LKM from `/proc/modules` and removes `/sys/module/<name>`. Implemented in `lifecycle.c::conceal_module()`. Applies once at `init_driver`; irreversible for the module's lifetime.

### `HIDE_VMAP` (default 1)

Unlinks the LKM's data vmap area from `vmap_area_list` (source of `/proc/vmallocinfo`) and, when the single-root form exists (kernels < 6.9), also `rb_erase()`s it from `vmap_area_root`. Probe is `&drv` (core `.bss`) so the module's `__init` section is untouched and `do_free_init` still cleans up correctly. Falls back to no-op if `vmap_area_list` is not in kallsyms. See `lifecycle.c::conceal_vmap()`.

### `HIDE_TASK` (default 1) — PID hider

`hide_task.c` registers a kprobe on `filldir64` and, when the entry name parses as a decimal PID in the hidden set, spoofs the return so `/proc` readdir cannot list it. Up to `HIDE_TASK_MAX_SLOTS` (8) PIDs. Direct `open("/proc/<pid>/...")` still works — this is a readdir-level hide, not a full-process cloak.

Client API (`driver.hide`):

- `add(pid)` — kprobe is lazily armed on first call, then the PID enters the hidden set.
- `remove(pid)`, `clear()`, `list()` — self-explanatory.

Ioctl range: `HIDE_PID_ADD=0x50`, `HIDE_PID_REMOVE=0x51`, `HIDE_PID_CLEAR=0x52`, `HIDE_PID_LIST=0x53`.

### `HIDE_KGSL_STRENGTH` (default 0) — KGSL/Adreno hider

Values:

- `0` — off. `DRV_CMD_HIDE_KGSL` returns `-EOPNOTSUPP`.
- `1` — retroactive `rb_erase`. `hide_kgsl_by_pid()` walks the two `kgsl_process_private` rbtrees held by `kgsl_driver` and erases the entry whose PID string matches. One-shot per client call; KGSL will re-create the entry if the same PID reopens a GPU context.
- `2` — proactive kprobes. `kgsl_process_init_sysfs`, `kgsl_process_init_debugfs`, and `sysfs_create_group` all pre-check `hide_task_contains(current->tgid)` and, for hidden PIDs, spoof `-ENOMEM` before the original runs. `sysfs_create_group` additionally walks the kobject parent chain (up to 7 levels) and only fires when a `"kgsl"` name is found in the ancestry, so unrelated sysfs creations pay a single lock-read.
- `3` — both.

`STRENGTH >= 2` requires `HIDE_TASK=1` (the proactive layer reads the shared hidden-PID list).

Versioned offsets for the `kgsl_driver` and `kgsl_process_private` structs live in `stealth.c`. The runtime `holder_ptr_looks_valid()` check guards against BSP drift.

## Hook APIs

`driver.hwbp` installs an AArch64 execute breakpoint for one target thread. Supports X0..X30, PC, SIMD V0..V31 low/high overrides, a 32-entry hit ring, idempotent override updates, and explicit remove/clear. `passThrough=false` is a fall-through-instruction-only early return valid at function entry; `passThrough=true` cannot combine with a PC override. `getHits()` captures raw entry registers before overrides. Tracker identity uses the kernel PID object and target `mm`, preventing numeric PID reuse and `execve()` redirection.

HWBP commands: `INSTALL=0x40`, `REMOVE=0x41`, `SET_OVERRIDE=0x42`, `GET_HITS=0x43`, `CLEAR_ALL=0x44`.

`driver.pteHook` installs a 32-byte constant-return stub in a private executable mapping. `returnConst<T>()` supports integral, enum, pointer, float, and double values; `returnVoid()` emits only a return. Stub starts with a BTI-compatible landing, validates one complete same-page private VMA, and records expected patched bytes. Reinstall, remove, and `clearAll()` refuse to overwrite a changed function.

PTE-hook commands: `INSTALL=0x48`, `REMOVE=0x49`, `CLEAR_ALL=0x4A`. Kind values: `CONST_U64=0`, reserved `TRAMPOLINE=1`, `CONST_FLOAT=2`, `CONST_DOUBLE=3`, `VOID_RET=4`.

Both APIs use access to the trusted driver fd as the permission boundary; they do not stop target threads, so callers must quiesce threads sharing the target `mm` while installing or removing a 32-byte patch.

## Benchmark snapshot

NP05J / Android 15 / kernel 6.6.56. Values in µs, mean per operation. Reference data, not a portability guarantee.

### Memory read

| Size | Driver | process_vm_readv | /proc/pid/mem |
| --- | ---: | ---: | ---: |
| 4 B | 0.699 | 1.162 | 1.518 |
| 1 KiB | 0.809 | 1.298 | 1.615 |
| 64 KiB | 12.293 | 15.762 | 23.481 |
| 1 MiB | 188.905 | 225.284 | 362.884 |
| 4 MiB | 796.633 | 815.044 | 1470.967 |

### Memory write

| Size | Driver | process_vm_writev |
| --- | ---: | ---: |
| 4 B | 0.710 | 1.166 |
| 4 KiB | 1.047 | 1.521 |
| 64 KiB | 12.651 | 15.875 |
| 1 MiB | 191.251 | 227.859 |

### MULTI_READ

| Entries | N × READ | MULTI_READ | Speedup |
| ---: | ---: | ---: | ---: |
| 8 | 5.913 | 1.819 | 3.25× |
| 128 | 92.547 | 12.573 | 7.36× |
| 512 | 373.199 | 46.071 | 8.10× |

### Hook ioctl latency

| Operation | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| PTE install/update | 4.063 | 4.219 | 5.156 |
| HWBP install | 9.688 | 13.438 | 2448.438 |
| HWBP SET_OVERRIDE | 0.834 | 0.938 | 0.938 |

## Layout

```text
driver/include/driver/uapi.h  shared kernel/userspace ABI
driver/src/lifecycle.c        module init + conceal_module + conceal_vmap
driver/src/comm.c             ioctl router + reboot()-magic handshake
driver/src/memory.c           pagewalk + process-memory R/W
driver/src/hwbp.c             hardware breakpoint subsystem
driver/src/user_hook.c        constant-return user-code hooks
driver/src/hide_task.c        filldir64 kprobe → /proc PID hider
driver/src/stealth.c          KGSL retroactive + proactive concealment
driver/src/sensor.c           HIDL/AIDL sensor uprobe
driver/src/input_synth.c      touch injection
driver/src/log.h              LOGE/LOGW/LOGN/LOGI/LOGD macros
client/src/Driver.{h,cpp}     userspace API (memory/touch/gyro/hwbp/pteHook/hide)
diagnostics/capture-kmsg.sh   Toybox-compatible kmsg capture helper
.github/workflows/build.yml   seven-KMI module + arm64 client CI
```

## Configurable knobs

```bash
make DRIVER_NAME=my-driver \
     TARGET_PKG='"cent.tmgp.sgame"' \
     HIDE_SELF_MODULE=1 HIDE_VMAP=1 HIDE_TASK=1 HIDE_KGSL_STRENGTH=0
```

`DRIVER_NAME` controls the module filename. `TARGET_PKG` selects the harvest package string. `REBOOT_MAGIC` controls the handshake. Concealment knobs are documented in the section above. Kbuild enforces `STRENGTH >= 2 → HIDE_TASK=1`.

## Caveats

The module has no unload entry point — kprobes, task work, and hook callbacks can retain module pointers. Reboot before replacing a loaded artefact. The memory path does not pin pages, so migration races and COW semantics remain. `HIDE_KGSL_STRENGTH >= 1` is not universal across Qualcomm BSPs; enable only after the runtime sanity checks pass. `diagnostics/capture-kmsg.sh` is a debug helper, not a production logger.

## License

GPL-2.0-only. See [LICENSE](LICENSE), [NOTICE.md](NOTICE.md), [CONTRIBUTING.md](CONTRIBUTING.md).
