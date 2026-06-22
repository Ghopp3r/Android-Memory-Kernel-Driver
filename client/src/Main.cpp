// SPDX-License-Identifier: GPL-2.0
#include <cctype>
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

static std::string prompt(const char* label) {
    std::printf("%s", label);
    std::fflush(stdout);
    char buf[256] = {0};
    if (!std::fgets(buf, sizeof(buf), stdin))
        return {};
    size_t n = std::strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
        buf[--n] = 0;
    return std::string(buf);
}

static bool isAllDigits(const std::string& s) {
    if (s.empty())
        return false;
    for (char c : s)
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    return true;
}

static std::optional<pid_t> resolvePackageToPid(const std::string& pkg) {
    DIR* d = ::opendir("/proc");
    if (!d)
        return std::nullopt;

    std::optional<pid_t> found;
    while (dirent* e = ::readdir(d)) {
        const char* n = e->d_name;
        if (n[0] < '0' || n[0] > '9')
            continue;

        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%s/cmdline", n);
        int fd = ::open(path, O_RDONLY);
        if (fd < 0)
            continue;

        char buf[256] = {0};
        ssize_t r = ::read(fd, buf, sizeof(buf) - 1);
        ::close(fd);
        if (r <= 0)
            continue;

        if (std::strncmp(buf, pkg.c_str(), pkg.size()) == 0) {
            found = static_cast<pid_t>(std::atoi(n));
            break;
        }
    }
    ::closedir(d);
    return found;
}

static void hexDump16(uint64_t addr, const uint8_t* buf) {
    std::printf("0x%016llx: ", static_cast<unsigned long long>(addr));
    for (int i = 0; i < 16; ++i)
        std::printf("%02x ", buf[i]);
    std::printf("\n");
}

int main() {
    driver.installHooks();

    std::string targetInput = prompt("Target (pid or package): ");
    pid_t pid = 0;
    if (isAllDigits(targetInput)) {
        pid = static_cast<pid_t>(std::atoi(targetInput.c_str()));
    } else if (auto found = resolvePackageToPid(targetInput)) {
        pid = *found;
        std::printf("Package: %s, Pid: %d\n", targetInput.c_str(), static_cast<int>(pid));
    } else {
        std::fprintf(stderr, "Target not found: %s\n", targetInput.c_str());
        return 1;
    }
    driver.setTarget(pid);

    std::string moduleName = prompt("Module (default libUE4.so): ");
    if (moduleName.empty())
        moduleName = "libUE4.so";

    auto base = driver.getModuleBase(moduleName);
    if (!base) {
        std::fprintf(stderr, "Module: %s, Status: not found\n", moduleName.c_str());
        return 2;
    }
    std::printf("Module: %s, Base: 0x%llx\n", moduleName.c_str(), static_cast<unsigned long long>(*base));

    uint8_t firstBytes[16] = {0};
    if (driver.readBytes(*base, firstBytes, sizeof(firstBytes)))
        hexDump16(*base, firstBytes);

    if (auto tls = driver.getTls())
        std::printf("Tls: 0x%llx\n", static_cast<unsigned long long>(*tls));

    if (auto magic = driver.read<uint32_t>(*base))
        std::printf("ElfMagic: 0x%08x\n", *magic);

    if (driver.touchDown(0, 100, 100) && driver.touchUp(0))
        std::printf("Touch: ok, Slot: 0, At: (100,100)\n");

    return 0;
}
