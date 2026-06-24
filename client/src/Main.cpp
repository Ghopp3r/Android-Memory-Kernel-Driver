// SPDX-License-Identifier: GPL-2.0
//
// Demo client for my-driver.ko. Exercises every sub-API of CDriver:
//   driver.memory.{read,write,readVmap,writeVmap,getModuleBase,getTls,...}
//   driver.touch.{down,move,up}
//   driver.gyro.{bind,bindAuto,write,isArmed}
//   driver.{open,installHooks,tearDown,setTarget,findTaskByComm,...}
//
// Drop-in pattern for new projects: copy Driver.{h,cpp} + SensorResolve.h,
// adapt the per-frame logic. No app-specific code here.

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "Driver.h"

constexpr const char* kDefaultPackage = "com.example.game";
constexpr const char* kDefaultModule  = "libUE4.so";

static std::string prompt(const char* label) {
    std::printf("%s", label);
    std::fflush(stdout);
    char buf[256] = {0};
    if (!std::fgets(buf, sizeof(buf), stdin)) return {};
    size_t n = std::strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
        buf[--n] = 0;
    return std::string(buf);
}

static bool promptYesNo(const char* label) {
    std::string a = prompt(label);
    return a == "y" || a == "Y" || a == "yes" || a == "YES";
}

static bool isAllDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

static std::optional<pid_t> GetPid(const std::string& pkg) {
    DIR* d = ::opendir("/proc");
    if (!d) return std::nullopt;
    std::optional<pid_t> found;
    while (dirent* e = ::readdir(d)) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
        int fd = ::open(path, O_RDONLY);
        if (fd < 0) continue;
        char buf[256] = {0};
        ssize_t r = ::read(fd, buf, sizeof(buf) - 1);
        ::close(fd);
        if (r > 0 && std::strncmp(buf, pkg.c_str(), pkg.size()) == 0) {
            found = static_cast<pid_t>(std::atoi(e->d_name));
            break;
        }
    }
    ::closedir(d);
    return found;
}

static void hexDump16(uint64_t addr, const uint8_t* buf) {
    std::printf("0x%016llx: ", static_cast<unsigned long long>(addr));
    for (int i = 0; i < 16; ++i) std::printf("%02x ", buf[i]);
    std::printf("\n");
}

int main() {
    if (!driver.open()) {
        std::fprintf(stderr, "driver.open failed: errno=%d (%s)\n", errno, std::strerror(errno));
        return 3;
    }
    std::printf("driver.open: ok\n");

    if (promptYesNo("Install hooks? [y/N]: ")) {
        std::printf("installHooks: %s\n", driver.installHooks() ? "ok" : "failed");
    }

    if (promptYesNo("Auto-bind gyro uprobe? [y/N]: ")) {
        if (driver.gyro.bindAuto())
            std::printf("gyro.bindAuto: armed\n");
        else
            std::printf("gyro.bindAuto: no candidate symbol in libsensorservice.so\n");
    }

    std::string targetInput = prompt(("Target (pid or package, default " + std::string(kDefaultPackage) + "): ").c_str());
    if (targetInput.empty()) targetInput = kDefaultPackage;
    pid_t pid = 0;
    if (isAllDigits(targetInput)) {
        pid = static_cast<pid_t>(std::atoi(targetInput.c_str()));
    } else if (auto found = GetPid(targetInput)) {
        pid = *found;
        std::printf("package: %s -> pid: %d\n", targetInput.c_str(), static_cast<int>(pid));
    } else {
        std::fprintf(stderr, "target not found: %s\n", targetInput.c_str());
        return 1;
    }
    driver.setTarget(pid);

    std::string moduleName = prompt(("Module (default " + std::string(kDefaultModule) + "): ").c_str());
    if (moduleName.empty()) moduleName = kDefaultModule;

    auto base = driver.memory.getModuleBase(moduleName);
    if (!base) {
        std::fprintf(stderr, "memory.getModuleBase: %s not found\n", moduleName.c_str());
        return 2;
    }
    std::printf("memory.getModuleBase: 0x%llx\n", static_cast<unsigned long long>(*base));

    uint8_t first[16] = {0};
    if (driver.memory.read(*base, first, sizeof(first))) {
        std::printf("memory.read 16B: ok\n");
        hexDump16(*base, first);
    } else {
        std::printf("memory.read: failed at 0x%llx\n", static_cast<unsigned long long>(*base));
    }

    if (auto tls = driver.memory.getTls())
        std::printf("memory.getTls: 0x%llx\n", static_cast<unsigned long long>(*tls));
    else
        std::printf("memory.getTls: unavailable\n");

    if (auto magic = driver.memory.read<uint32_t>(*base))
        std::printf("memory.read<u32> (ELF magic): 0x%08x\n", *magic);

    if (promptYesNo("Inject test touch at (100,100)? [y/N]: ")) {
        bool ok = driver.touch.down(0, 100, 100) && driver.touch.up(0);
        std::printf("touch.down + touch.up: %s\n", ok ? "ok" : "failed");
    }

    if (driver.gyro.isArmed() && promptYesNo("Inject 0.5 rad/s gyro spoof for 2s? [y/N]: ")) {
        driver.gyro.write(0.5f, 0.0f, true);
        ::sleep(2);
        driver.gyro.write(0.0f, 0.0f, false);
        std::printf("gyro.write: cycled\n");
    }

    std::printf("done\n");
    return 0;
}
