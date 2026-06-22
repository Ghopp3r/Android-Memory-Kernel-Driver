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
    CDriver() = default;
    ~CDriver();

    CDriver(const CDriver&) = delete;
    CDriver& operator=(const CDriver&) = delete;
    CDriver(CDriver&& other) noexcept;
    CDriver& operator=(CDriver&& other) noexcept;

    bool open();
    void close();

    bool isOpen() const {
        return m_fd >= 0;
    }

    void setTarget(pid_t pid) {
        m_targetPid = pid;
    }

    pid_t target() const {
        return m_targetPid;
    }

    template<typename T> std::optional<T> read(uint64_t addr);
    template<typename T> bool write(uint64_t addr, const T& value);
    template<typename T> std::optional<T> readVmap(uint64_t addr);
    template<typename T> bool writeVmap(uint64_t addr, const T& value);

    bool readBytes(uint64_t addr, void* out, size_t len);
    bool writeBytes(uint64_t addr, const void* in, size_t len);
    bool readBytesVmap(uint64_t addr, void* out, size_t len);
    bool writeBytesVmap(uint64_t addr, const void* in, size_t len);

    std::optional<uint64_t> getModuleBase(const std::string& name);
    std::optional<pid_t> findTaskByComm(const std::string& comm);
    std::optional<uint64_t> getTls();
    std::optional<uint64_t> readVmaCookie(uint64_t addr);

    std::vector<uint64_t> multiRead(const std::vector<uint64_t>& addrs);
    std::vector<VmaInfo> dumpVmas();
    bool hideKgsl();

    bool installHooks();
    bool tearDown();
    bool installSigsegvSuppress();

    bool touchDown(int slot, int x, int y);
    bool touchUp(int slot);
    bool touchMove(int slot, int x, int y);

    bool setGyroEnable(bool enable);
    bool setGyroDelta(float x, float y);
    bool bindSensorHook(uint64_t libOffset, int eventType);

private:
    int doIoctl(unsigned int cmd, drv_ioctl_req* req);

    int m_fd = -1;
    pid_t m_targetPid = 0;
};

extern CDriver driver;

template<typename T>
std::optional<T> CDriver::read(uint64_t addr) {
    T value{};
    if (!readBytes(addr, &value, sizeof(T)))
        return std::nullopt;
    return value;
}

template<typename T>
bool CDriver::write(uint64_t addr, const T& value) {
    return writeBytes(addr, &value, sizeof(T));
}

template<typename T>
std::optional<T> CDriver::readVmap(uint64_t addr) {
    T value{};
    if (!readBytesVmap(addr, &value, sizeof(T)))
        return std::nullopt;
    return value;
}

template<typename T>
bool CDriver::writeVmap(uint64_t addr, const T& value) {
    return writeBytesVmap(addr, &value, sizeof(T));
}
