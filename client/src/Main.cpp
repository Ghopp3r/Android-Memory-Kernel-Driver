// SPDX-License-Identifier: GPL-2.0
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

#ifndef HACK_CLIENT_TARGET_PACKAGE
#define HACK_CLIENT_TARGET_PACKAGE "com.example.game"
#endif

#ifndef HACK_CLIENT_TARGET_MODULE
#define HACK_CLIENT_TARGET_MODULE "libUE4.so"
#endif

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

static std::optional<uint64_t> parseAddress(const std::string& s) {
    if (s.empty())
        return std::nullopt;

    const char* begin = s.c_str();
    while (*begin == ' ' || *begin == '\t')
        ++begin;
    if (*begin == '\0')
        return std::nullopt;

    errno = 0;
    char* end = nullptr;
    unsigned long long value = std::strtoull(begin, &end, 0);
    if (errno != 0 || end == begin)
        return std::nullopt;
    while (*end == ' ' || *end == '\t')
        ++end;
    if (*end != '\0' || value == 0)
        return std::nullopt;
    return static_cast<uint64_t>(value);
}

int main() {
    driver.installHooks();

    std::string targetPrompt = std::string("Target (pid or package, default ") + HACK_CLIENT_TARGET_PACKAGE + "): ";
    std::string targetInput = prompt(targetPrompt.c_str());
    if (targetInput.empty())
        targetInput = HACK_CLIENT_TARGET_PACKAGE;

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

    std::string modulePrompt = std::string("Module (default ") + HACK_CLIENT_TARGET_MODULE + "): ";
    std::string moduleName = prompt(modulePrompt.c_str());
    if (moduleName.empty())
        moduleName = HACK_CLIENT_TARGET_MODULE;

    auto base = driver.getModuleBase(moduleName);
    if (!base) {
        std::fprintf(stderr, "Module: %s, Status: not found\n", moduleName.c_str());
        std::string baseInput = prompt("Module base (hex, empty to exit): ");
        base = parseAddress(baseInput);
        if (!base) {
            std::fprintf(stderr, "Module base not provided\n");
            return 2;
        }
        std::printf("Module: %s, ManualBase: 0x%llx\n", moduleName.c_str(), static_cast<unsigned long long>(*base));
    } else {
        std::printf("Module: %s, Base: 0x%llx\n", moduleName.c_str(), static_cast<unsigned long long>(*base));
    }

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
