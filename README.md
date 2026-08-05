# my-driver

Android ARM64 loadable kernel module with privileged process-memory R/W, touch injection, sensor spoofing, page-fault harvest, optional KGSL concealment, and two explicit hook APIs. The userspace fd is created through the existing magic `reboot()` handshake; no device node is required. `HIDE_SELF_MODULE=1` remains the default, while `HIDE_KGSL=0` keeps the vendor-specific path opt-in.

## Build matrix

The GitHub workflow builds one module against each supported Android KMI and compiles the Android arm64 client:

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`

Only `android15-6.6` has current device runtime coverage (NP05J / Android 15 / kernel 6.6.56). The other legs are compile-validated by Actions.

## Build

The repository intentionally does not build kernel code on the host. Use GitHub Actions or the matching DDK image:

```bash
cd driver
./build.sh android15-6.6
HIDE_SELF_MODULE=0 HIDE_KGSL=1 ./build.sh android15-6.6
```

The default DDK release is `20251104`; it is required by the `android16-6.12` KCFI checks. The workflow publishes one `.ko` artifact per KMI and one static arm64 userspace client. The tracked `scripts/` test tools were removed from the repository and are ignored locally.

## Userspace client

Build with the Android NDK and CMake:

```bash
cmake -S client -B out/client -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
cmake --build out/client
```

The client opens the fd lazily. `findPidByPackage()` matches the complete `argv[0]`; after `setTarget(pid)`, the existing APIs are available as `driver.memory`, `driver.touch`, and `driver.gyro`.

## Hook APIs

`driver.hwbp` installs an AArch64 execute breakpoint for one target thread. It supports X0..X30, PC, and SIMD V0..V31 low/high 64-bit overrides, a 32-entry hit ring, idempotent override updates, and explicit remove/clear operations. v1 pass-through accepts only fall-through instructions; branches, returns, exceptions, watchpoints, compat tasks, and non-executable mappings return an error. `getHits()` captures raw entry registers before overrides. Tracker identity uses the kernel PID object and target `mm`, preventing numeric PID reuse and `execve()` redirection.

The HWBP commands are `INSTALL=0x40`, `REMOVE=0x41`, `SET_OVERRIDE=0x42`, `GET_HITS=0x43`, and `CLEAR_ALL=0x44`. `passThrough=false` is an early return and is valid only at a function entry. `passThrough=true` cannot be combined with a PC override; if the trapped instruction faults or never reaches `addr+4`, remove and reinstall the tracker before reuse.

`driver.pteHook` installs a 32-byte constant-return stub in a private executable mapping. `returnConst<T>()` supports integral, enum, pointer, float, and double values; `returnVoid()` emits only a return. The trampoline kind is reserved for a future ABI. The stub starts with a BTI-compatible landing instruction, validates one complete same-page private VMA, and records expected patched bytes. Reinstall, remove, and global `clearAll()` refuse to overwrite a changed function and report restoration errors.

The PTE-hook commands are `INSTALL=0x48`, `REMOVE=0x49`, and `CLEAR_ALL=0x4A`. The fixed v1 kind values are `CONST_U64=0`, reserved `TRAMPOLINE=1`, `CONST_FLOAT=2`, `CONST_DOUBLE=3`, and `VOID_RET=4`. The caller must ensure that the entry has 32 replaceable bytes; the driver validates the mapping, not function boundaries.

Both APIs use access to the trusted driver fd as their permission boundary. They do not stop target threads: callers must quiesce all threads sharing the target `mm` while installing or removing a 32-byte patch. Forked private COW mappings and remapping are outside the v1 registry model. Closing the C++ client does not clear global hooks.

## Benchmark snapshot

Fresh single-device measurements on NP05J / Android 15 / kernel 6.6.56. Values are microseconds; read and write values are mean per operation. They are comparison data, not portability or safety guarantees.

### Memory read

| Size | Driver | process_vm_readv | /proc/pid/mem |
| --- | ---: | ---: | ---: |
| 4 B | 0.699 | 1.162 | 1.518 |
| 16 B | 0.711 | 1.186 | 1.515 |
| 64 B | 0.738 | 1.184 | 1.508 |
| 256 B | 0.735 | 1.203 | 1.510 |
| 1 KiB | 0.809 | 1.298 | 1.615 |
| 4 KiB | 1.142 | 1.613 | 1.999 |
| 16 KiB | 2.795 | 3.867 | 5.954 |
| 64 KiB | 12.293 | 15.762 | 23.481 |
| 256 KiB | 46.200 | 57.262 | 90.411 |
| 1 MiB | 188.905 | 225.284 | 362.884 |
| 4 MiB | 796.633 | 815.044 | 1470.967 |

### Memory write

| Size | Driver | process_vm_writev |
| --- | ---: | ---: |
| 4 B | 0.710 | 1.166 |
| 16 B | 0.721 | 1.178 |
| 64 B | 0.718 | 1.181 |
| 256 B | 0.724 | 1.192 |
| 1 KiB | 0.790 | 1.245 |
| 4 KiB | 1.047 | 1.521 |
| 64 KiB | 12.651 | 15.875 |
| 1 MiB | 191.251 | 227.859 |

### MULTI_READ

| Entries | N x READ | MULTI_READ | Speedup |
| ---: | ---: | ---: | ---: |
| 8 | 5.913 | 1.819 | 3.25x |
| 32 | 23.167 | 3.868 | 5.99x |
| 128 | 92.547 | 12.573 | 7.36x |
| 512 | 373.199 | 46.071 | 8.10x |

### Hook ioctl latency

| Operation | p50 | p95 | p99 | Min | Max | Samples |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PTE install/update | 4.063 | 4.219 | 5.156 | 3.906 | 17.552 | 200 |
| HWBP install | 9.688 | 13.438 | 2448.438 | 8.802 | 2448.438 | 100 |
| HWBP SET_OVERRIDE | 0.834 | 0.938 | 0.938 | 0.781 | 1.250 | 1000 |

The hook harness measures ioctl latency only; treat its results as reference data, not a portability or safety guarantee.

## Layout

```text
driver/include/driver/uapi.h  shared kernel/userspace ABI
driver/src/memory.c           pagewalk and process-memory R/W
driver/src/hwbp.c             hardware breakpoint subsystem
driver/src/user_hook.c        constant-return user-code hooks
driver/src/sensor.c           HIDL/AIDL sensor uprobe
driver/src/input_synth.c      touch injection
driver/src/stealth.c          optional KGSL concealment
client/src/Driver.*           userspace API and ioctl wrappers
diagnostics/capture-kmsg.sh   Toybox-compatible kmsg capture helper
.github/workflows/build.yml   seven-KMI module and arm64 client build
```

## Configurable knobs

```bash
make DRIVER_NAME=my-driver TARGET_PKG='"cent.tmgp.sgame"' HIDE_SELF_MODULE=1 HIDE_KGSL=0
```

`DRIVER_NAME` controls the module filename. `TARGET_PKG` selects the harvest package string. `REBOOT_MAGIC` controls the handshake. `HIDE_SELF_MODULE` toggles module-list/sysfs concealment. `HIDE_KGSL` enables the versioned vendor-specific KGSL path only when its offsets match the target device.

## Caveats

The module has no unload entry point because kprobes, task work, and hook callbacks can retain module pointers; reboot before replacing a loaded artifact. The memory path intentionally does not pin pages, so migration races and COW semantics remain. `HIDE_KGSL=1` is not universal across Qualcomm BSPs and should be enabled only after its runtime sanity checks pass. `diagnostics/capture-kmsg.sh` is a debugging helper, not a production logger.

## License

GPL-2.0-only. See [LICENSE](LICENSE), [NOTICE.md](NOTICE.md), and [CONTRIBUTING.md](CONTRIBUTING.md).
