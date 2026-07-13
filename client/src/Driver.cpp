// SPDX-License-Identifier: GPL-2.0
#include "Driver.h"
#include "SensorResolve.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

CDriver driver;

CDriver::CDriver() : memory(*this), touch(*this), gyro(*this) {}

CDriver::~CDriver() {
    close();
}

// Magic-handshake bootstrap: __arm64_sys_reboot kprobe pre-handler matches
// inner_regs[0]==MAGIC1 && inner_regs[1]==MAGIC2 and writes the freshly-installed
// anon-inode fd into the userspace pointer at inner_regs[3]. Reachable from adb
// shell uid; bionic seccomp blocks __NR_reboot for Zygote-forked app uids.
bool CDriver::open() {
    if (m_fd >= 0) return true;
    int newFd = -1;
    ::syscall(SYS_reboot, DRIVER_REBOOT_MAGIC1, DRIVER_REBOOT_MAGIC2, 0L, &newFd);
    if (newFd >= 0) { m_fd = newFd; return true; }
    return false;
}

void CDriver::close() {
    if (m_fd >= 0) { ::close(m_fd); m_fd = -1; }
}

int CDriver::doIoctl(unsigned int cmd, drv_ioctl_req* req) {
    if (m_fd < 0 && !open()) return -1;
    return ::ioctl(m_fd, cmd, req);
}

int CDriver::doIoctlRaw(unsigned int cmd, void* arg) {
    if (m_fd < 0 && !open()) return -1;
    return ::ioctl(m_fd, cmd, arg);
}

bool CDriver::installHooks() {
    drv_ioctl_req req{};
    return doIoctl(DRV_CMD_INSTALL_HOOKS, &req) >= 0;
}

bool CDriver::tearDown() {
    drv_ioctl_req req{};
    return doIoctl(DRV_CMD_TEAR_DOWN, &req) >= 0;
}

bool CDriver::installSigsegvSuppress() {
    drv_ioctl_req req{};
    return doIoctl(DRV_CMD_INSTALL_SIGSEGV_SUPPRESS, &req) >= 0;
}

bool CDriver::hideKgsl() {
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_targetPid);
    if (doIoctl(DRV_CMD_HIDE_KGSL, &req) < 0) return false;
    return static_cast<int64_t>(req.size) >= 0;
}

std::optional<pid_t> CDriver::findTaskByComm(const std::string& comm) {
    drv_ioctl_req req{};
    req.addr = reinterpret_cast<uint64_t>(comm.c_str());
    if (doIoctl(DRV_CMD_FIND_TASK_BY_COMM, &req) < 0) return std::nullopt;
    if (req.size == 0 || req.size > 0x7fffffffULL) return std::nullopt;
    return static_cast<pid_t>(req.size);
}

std::optional<pid_t> CDriver::findPidByPackage(const std::string& package) {
    if (package.empty() || package.size() > DRV_PACKAGE_NAME_MAX ||
        package.find('\0') != std::string::npos) {
        errno = package.size() > DRV_PACKAGE_NAME_MAX ? ENAMETOOLONG : EINVAL;
        return std::nullopt;
    }

    drv_find_pid_req req{};
    std::memcpy(req.package, package.data(), package.size());
    if (doIoctlRaw(DRV_CMD_FIND_PID_BY_PACKAGE, &req) < 0)
        return std::nullopt;
    if (req.pid <= 0) {
        errno = ESRCH;
        return std::nullopt;
    }
    return static_cast<pid_t>(req.pid);
}

bool CDriver::Memory::read(uint64_t addr, void* out, size_t len) {
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    req.addr = addr;
    req.buf = reinterpret_cast<uint64_t>(out);
    req.size = len;
    if (m_d.doIoctl(DRV_CMD_READ_MEM_LINEAR, &req) < 0) return false;
    return req.size == len;
}

bool CDriver::Memory::write(uint64_t addr, const void* in, size_t len) {
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    req.addr = addr;
    req.buf = reinterpret_cast<uint64_t>(in);
    req.size = len;
    if (m_d.doIoctl(DRV_CMD_WRITE_MEM_LINEAR, &req) < 0) return false;
    return req.size == len;
}

bool CDriver::Memory::readVmap(uint64_t addr, void* out, size_t len) {
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    req.addr = addr;
    req.buf = reinterpret_cast<uint64_t>(out);
    req.size = len;
    if (m_d.doIoctl(DRV_CMD_READ_MEM_VMAP, &req) < 0) return false;
    return req.size == len;
}

bool CDriver::Memory::writeVmap(uint64_t addr, const void* in, size_t len) {
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    req.addr = addr;
    req.buf = reinterpret_cast<uint64_t>(in);
    req.size = len;
    if (m_d.doIoctl(DRV_CMD_WRITE_MEM_VMAP, &req) < 0) return false;
    return req.size == len;
}

std::optional<uint64_t> CDriver::Memory::getModuleBase(const std::string& name) {
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    req.addr = reinterpret_cast<uint64_t>(name.c_str());
    if (m_d.doIoctl(DRV_CMD_GET_MODULE_BASE, &req) < 0 || req.size == 0)
        return std::nullopt;
    return req.size;
}

std::optional<uint64_t> CDriver::Memory::getTls() {
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    if (m_d.doIoctl(DRV_CMD_GET_TLS, &req) < 0 || req.size == 0)
        return std::nullopt;
    return req.size;
}

std::optional<uint64_t> CDriver::Memory::readVmaCookie(uint64_t addr) {
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    req.addr = addr;
    if (m_d.doIoctl(DRV_CMD_READ_VMA_COOKIE, &req) < 0) return std::nullopt;
    return req.size;
}

std::vector<uint64_t> CDriver::Memory::multiRead(const std::vector<uint64_t>& addrs) {
    std::vector<uint64_t> out(addrs.size(), 0);
    if (addrs.empty()) return out;
    std::vector<drv_multi_read_req> descs(addrs.size());
    for (size_t i = 0; i < addrs.size(); ++i) {
        descs[i].user_dst = reinterpret_cast<uint64_t>(&out[i]);
        descs[i].src_va = addrs[i];
        descs[i].len = sizeof(uint64_t);
    }
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    req.buf = reinterpret_cast<uint64_t>(descs.data());
    req.extra = descs.size();
    if (m_d.doIoctl(DRV_CMD_MULTI_READ, &req) < 0 || req.size != 1) out.clear();
    return out;
}

std::vector<VmaInfo> CDriver::Memory::dumpVmas() {
    constexpr size_t kCap = 1024;
    std::vector<VmaInfo> entries(kCap);
    drv_ioctl_req req{};
    req.pid = static_cast<uint32_t>(m_d.m_targetPid);
    req.buf = reinterpret_cast<uint64_t>(entries.data());
    req.size = entries.size() * sizeof(VmaInfo);
    if (m_d.doIoctl(DRV_CMD_DUMP_VMAS, &req) < 0) { entries.clear(); return entries; }
    entries.resize(req.size / sizeof(VmaInfo));
    return entries;
}

// Kernel comm.c does copy_from_user(&tr, arg, sizeof(drv_touch_inject_req)) —
// pass &tr raw via doIoctlRaw. The legacy &drv_ioctl_req path stuffed garbage
// pointer bits into x/y as the kernel read 16 bytes from the wrong struct.
bool CDriver::Touch::down(int slot, int x, int y, int pressure) {
    drv_touch_inject_req tr{};
    tr.slot_id = static_cast<uint32_t>(slot);
    tr.x = static_cast<uint32_t>(x);
    tr.y = static_cast<uint32_t>(y);
    tr.pressure = static_cast<uint32_t>(pressure);
    return m_d.doIoctlRaw(DRV_CMD_TOUCH_DOWN, &tr) >= 0;
}

bool CDriver::Touch::move(int slot, int x, int y) {
    drv_touch_inject_req tr{};
    tr.slot_id = static_cast<uint32_t>(slot);
    tr.x = static_cast<uint32_t>(x);
    tr.y = static_cast<uint32_t>(y);
    return m_d.doIoctlRaw(DRV_CMD_TOUCH_MOVE, &tr) >= 0;
}

bool CDriver::Touch::up(int slot) {
    drv_touch_inject_req tr{};
    tr.slot_id = static_cast<uint32_t>(slot);
    return m_d.doIoctlRaw(DRV_CMD_TOUCH_UP, &tr) >= 0;
}

// Repeating the same offset/layout bind is idempotent kernel-side; a different
// bind is rejected. isArmed() flips on the first successful registration so
// the UI can disable gyro features when libsensorservice has no matching symbol.
bool CDriver::Gyro::bind(uint64_t probeOffset, int layoutProfile) {
    drv_ioctl_req req{};
    req.pid = 100;
    req.addr = probeOffset;
    req.size = static_cast<uint64_t>(layoutProfile);
    if (m_d.doIoctl(DRV_CMD_SENSOR_BIND, &req) < 0) return false;
    m_armed = true;
    return true;
}

bool CDriver::Gyro::bindAuto() {
    struct Candidate {
        const char* symbol;
        uint32_t layout;
    };
    static const Candidate kCandidates[] = {
        {
            "_ZN7android8hardware7sensors14implementation20convertToSensorEventERKN4aidl7android8hardware7sensors5EventEP15sensors_event_t",
            DRV_SENSOR_LAYOUT_AIDL_V1,
        },
        {
            "_ZN7android8hardware7sensors4V1_014implementation20convertToSensorEventERKNS2_5EventEP15sensors_event_t",
            DRV_SENSOR_LAYOUT_HIDL_V1,
        },
    };

    for (const Candidate& candidate : kCandidates) {
        const char* symbol = candidate.symbol;
        uint64_t off = GetSymbolOffset("/system/lib64/libsensorservice.so", &symbol, 1, nullptr);
        if (off)
            return bind(off, candidate.layout);
    }
    return false;
}

bool CDriver::Gyro::write(float dx, float dy, bool enable) {
    uint32_t xb, yb;
    std::memcpy(&xb, &dx, sizeof(xb));
    std::memcpy(&yb, &dy, sizeof(yb));
    drv_ioctl_req req{};
    req.pid = 0;
    req.addr = static_cast<uint64_t>(xb);
    req.size = static_cast<uint64_t>(yb);
    req.extra = enable ? 1 : 0;
    return m_d.doIoctl(DRV_CMD_SENSOR_BIND, &req) >= 0;
}
