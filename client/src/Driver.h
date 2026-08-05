// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <sys/types.h>
#include <type_traits>
#include <vector>

#include "driver/uapi.h"

struct VmaInfo {
    uint64_t start = 0;
    uint64_t end = 0;
};

class CDriver {
public:
    class Memory {
    public:
        Memory(CDriver& d) : m_d(d) {}

        bool read(uint64_t addr, void* out, size_t len);
        bool write(uint64_t addr, const void* in, size_t len);
        bool readVmap(uint64_t addr, void* out, size_t len);
        bool writeVmap(uint64_t addr, const void* in, size_t len);

        std::optional<uint64_t> getModuleBase(const std::string& name);
        std::optional<uint64_t> getTls();
        std::optional<uint64_t> readVmaCookie(uint64_t addr);
        std::vector<uint64_t> multiRead(const std::vector<uint64_t>& addrs);
        std::vector<VmaInfo> dumpVmas();

        template<typename T>
        std::optional<T> read(uint64_t addr) {
            T v{};
            if (!read(addr, &v, sizeof(T))) return std::nullopt;
            return v;
        }
        template<typename T>
        bool write(uint64_t addr, const T& v) { return write(addr, &v, sizeof(T)); }
        template<typename T>
        std::optional<T> readVmap(uint64_t addr) {
            T v{};
            if (!readVmap(addr, &v, sizeof(T))) return std::nullopt;
            return v;
        }
        template<typename T>
        bool writeVmap(uint64_t addr, const T& v) { return writeVmap(addr, &v, sizeof(T)); }

    private:
        bool writeChunked(unsigned int cmd, uint64_t addr, const void* in, size_t len);
        CDriver& m_d;
    };

    class Touch {
    public:
        Touch(CDriver& d) : m_d(d) {}
        bool down(int slot, int x, int y, int pressure = 50);
        bool move(int slot, int x, int y);
        bool up(int slot);
    private:
        CDriver& m_d;
    };

    class Gyro {
    public:
        Gyro(CDriver& d) : m_d(d) {}
        bool bind(uint64_t probeOffset, int layoutProfile);
        bool bindAuto();
        bool write(float dx, float dy, bool enable);
        bool isArmed() const { return m_armed; }
    private:
        CDriver& m_d;
        bool m_armed = false;
    };

    class Hwbp {
    public:
        Hwbp(CDriver& d) : m_d(d) {}
        bool install(uint64_t addr, const std::vector<drv_hwbp_reg_override>& overrides, bool passThrough = false, uint32_t bpType = DRV_HWBP_TYPE_EXECUTE, uint32_t bpLen = DRV_HWBP_LEN_EXECUTE);
        bool setOverride(uint64_t addr, const std::vector<drv_hwbp_reg_override>& overrides);
        bool remove(uint64_t addr);
        bool clearAll();
        std::vector<drv_hwbp_hit> getHits(uint64_t addr, size_t maxHits = DRV_HWBP_HIT_RING_SLOTS);
    private:
        CDriver& m_d;
    };

    class PteHook {
    public:
        PteHook(CDriver& d) : m_d(d) {}
        template<typename T> bool returnConst(uint64_t addr, T value);
        bool returnVoid(uint64_t addr);
        bool install(uint64_t addr, uint32_t kind, uint64_t value);
        bool remove(uint64_t addr);
        bool clearAll();
    private:
        CDriver& m_d;
    };

    CDriver();
    ~CDriver();
    CDriver(const CDriver&) = delete;
    CDriver& operator=(const CDriver&) = delete;

    bool open();
    void close();
    bool isOpen() const { return m_fd >= 0; }
    void setTarget(pid_t pid) { m_targetPid = pid; }
    pid_t target() const { return m_targetPid; }

    bool installHooks();
    bool tearDown();
    bool installSigsegvSuppress();
    bool hideKgsl();
    std::optional<pid_t> findTaskByComm(const std::string& comm);
    std::optional<pid_t> findPidByPackage(const std::string& package);

    Memory memory;
    Touch touch;
    Gyro gyro;
    Hwbp hwbp;
    PteHook pteHook;

private:
    int doIoctl(unsigned int cmd, drv_ioctl_req* req);
    int doIoctlRaw(unsigned int cmd, void* arg);

    int m_fd = -1;
    pid_t m_targetPid = 0;
};

extern CDriver driver;

static_assert(sizeof(drv_hwbp_reg_override) == 16);
static_assert(sizeof(drv_hwbp_install_req) == 192);
static_assert(sizeof(drv_hwbp_hit) == 280);
static_assert(sizeof(drv_pte_hook_install_req) == 40);

template<typename T>
bool CDriver::PteHook::returnConst(uint64_t addr, T value) {
    static_assert(sizeof(T) <= sizeof(uint64_t), "returnConst value must fit in an AArch64 return register");
    if constexpr (std::is_same_v<std::remove_cv_t<T>, float>) {
        uint32_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        return install(addr, DRV_PTE_HOOK_CONST_FLOAT, bits);
    } else if constexpr (std::is_same_v<std::remove_cv_t<T>, double>) {
        uint64_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        return install(addr, DRV_PTE_HOOK_CONST_DOUBLE, bits);
    } else {
        static_assert(std::is_integral_v<T> || std::is_enum_v<T> || std::is_pointer_v<T> || std::is_same_v<std::remove_cv_t<T>, std::nullptr_t>, "returnConst requires an integer, enum, pointer, float, or double");
        if constexpr (std::is_pointer_v<T>) return install(addr, DRV_PTE_HOOK_CONST_U64, reinterpret_cast<uint64_t>(value));
        else if constexpr (std::is_same_v<std::remove_cv_t<T>, std::nullptr_t>) return install(addr, DRV_PTE_HOOK_CONST_U64, 0);
        else return install(addr, DRV_PTE_HOOK_CONST_U64, static_cast<uint64_t>(value));
    }
}
