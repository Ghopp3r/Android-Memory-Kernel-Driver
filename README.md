# my-driver

Android ARM64 loadable kernel module exposing privileged process-memory,
input-injection, sensor-spoofing and page-fault-harvest primitives to a
controlling userspace client over an `ioctl()` channel obtained via a
magic `reboot()` handshake (no `/dev` node, no `lsmod` visibility).

Field-based source against GKI kernel headers — one source tree builds
seven KMI variants via the Docker DDK image. Code uses `task->mm` /
`dev->event_lock` / `pgd_offset(...)` etc. directly; per-kernel struct
layout is the compiler's problem at build time.

## Build matrix

| KMI                | Kernel | Android |
| ------------------ | ------ | ------- |
| `android12-5.10`   | 5.10   | 12      |
| `android13-5.10`   | 5.10   | 13      |
| `android13-5.15`   | 5.15   | 13      |
| `android14-5.15`   | 5.15   | 14      |
| `android14-6.1`    | 6.1    | 14      |
| `android15-6.6`    | 6.6    | 15      |
| `android16-6.12`   | 6.12   | 16      |

## Quick start — Docker DDK

```bash
cd driver
./build.sh android15-6.6        # or any KMI from the table
# -> driver/my-driver.ko
```

Equivalent one-liner:

```bash
docker run --rm -v "$PWD/driver:/work" -w /work \
    ghcr.io/ylarod/ddk:android15-6.6-20251016 make
```

## Quick start — GitHub Actions

Push to a GitHub repo. The included workflow
(`.github/workflows/build.yml`) runs all seven KMI legs in parallel and
uploads `my-driver-<kmi>.ko` as an artifact per leg. Trigger manually
via `workflow_dispatch` to pick a specific DDK image release tag.

## Userspace client

```bash
cd client
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30
cmake --build build
# -> client/build/my-driver-client
adb push build/my-driver-client /data/local/tmp/
```

The client uses a small RAII C++ class. Global instance `driver` opens
the ioctl fd lazily on first use:

```cpp
#include "Driver.h"

driver.setTarget(pid);
auto base = driver.getModuleBase("libUE4.so");
if (base) {
    uint32_t magic = driver.read<uint32_t>(*base).value_or(0);
}
driver.touchDown(0, 100, 200);
driver.touchUp(0);
```

## Layout

```
driver/
  Kbuild               kbuild objs list + ccflags
  Makefile             out-of-tree entry; honours $KERNEL_SRC from DDK image
  build.sh             docker convenience wrapper
  include/driver/
    uapi.h             shared kernel<->userspace ioctl surface
    types.h            internal driver state types
  src/
    compat/compat.h    LINUX_VERSION_CODE gates + driver-private constants
    lifecycle.c        module init/exit + self-conceal
    comm.c             reboot() handshake + dispatch_ioctl router
    memory.c           process pagewalk + read/write/multi_read
    uaccess_target.c   TTBR0-swap _copy_*_user wrappers
    vfs_hijack.c       /dev/input/event* read interception
    input_synth.c      synthetic MT event injection via kprobes
    sensor.c           gyro spoofing via libsensorservice.so uprobe
    harvest.c          page-fault address harvest for the target app
    stealth.c          GPU (KGSL/Adreno) process concealment
    hook_engine.c      KernelPatch-style inline hooks (relocate_inst + relo_*)
    kallsym.c          kallsyms_lookup_name via kprobe trick

client/
  CMakeLists.txt
  src/
    Driver.h           CDriver class + global `driver`
    Driver.cpp         ioctl wrappers
    Main.cpp           interactive demo (prompt for pid/package, run ops)

.github/workflows/build.yml   7-KMI matrix CI
```

## Configurable knobs

```bash
make DRIVER_NAME=my-driver TARGET_PKG=cent.tmgp.sgame
```

| variable | default | what it sets |
| --- | --- | --- |
| `DRIVER_NAME` | `my-driver` | output `.ko` filename + `__this_module.name` |
| `TARGET_PKG`  | `cent.tmgp.sgame` | package the harvest path activates on |

## License

GPL-2.0-only. See `LICENSE`.
