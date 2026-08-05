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

## Latest validation

| Check | Environment | Result |
| --- | --- | --- |
| Build matrix | [Actions #71](https://github.com/Ghopp3r/Android-Memory-Kernel-Driver/actions/runs/31043129620) | 7 kernel targets and the arm64 client passed |
| Core runtime probe | NP05J, Android 15, kernel 6.6.56 | 7/7 passed: memory R/W, PTE install/remove, HWBP install/get-hits/remove |
| Hook stress benchmark | Same device and fresh 6.6 artifact | Completed PTE update/remove and HWBP install/set loops |
| Kernel log after tests | Same boot session | No driver errors, kernel BUG, Oops, or panic |

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

These are historical single-device measurements on NP05J / Android 15 / kernel 6.6.56 and are not portability or safety guarantees. Driver/process_vm/procmem mean per-operation read times in microseconds were 4 B `0.88/1.50/1.53`, 16 B `0.87/1.50/1.61`, 256 B `0.90/1.54/1.75`, 4 KiB `1.41/2.05/2.36`, 16 KiB `3.35/4.76/6.79`, 64 KiB `14.7/19.0/27.8`, 1 MiB `223/270/418`, and 4 MiB `910/992/1683`. Driver/process_vm mean write times were 0.87/1.52 microseconds for 4 B, 1.28/1.94 for 4 KiB, 15.4/19.2 for 64 KiB, and 222/269 for 1 MiB.

`MULTI_READ` sequential/driver mean batch times were 7.0/2.2 microseconds for 8 entries, 27.9/4.7 for 32, 114/15.0 for 128, and 441/55.1 for 512. Historical hook measurements were PTE 5/5/6 microseconds p50/p95/p99 (mostly reinstall/update), cold HWBP install 13/70/736, and `SET_OVERRIDE` 0.78/0.78/0.78. The old hook harness was fail-open in places and predates the current hardening, so its numbers are references rather than current guarantees.

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
