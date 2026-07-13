// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>
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
    Touch  touch;
    Gyro   gyro;

private:
    int doIoctl(unsigned int cmd, drv_ioctl_req* req);
    int doIoctlRaw(unsigned int cmd, void* arg);

    int m_fd = -1;
    pid_t m_targetPid = 0;
};

extern CDriver driver;
