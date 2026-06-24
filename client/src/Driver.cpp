// SPDX-License-Identifier: GPL-2.0
#include "Driver.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>

static constexpr unsigned long RebootMagic1 = DRIVER_REBOOT_MAGIC1;
static constexpr unsigned long RebootMagic2 = DRIVER_REBOOT_MAGIC2;
static constexpr size_t VmaDumpEntries = 1024;

static drv_ioctl_req makeReq(pid_t pid) {
    drv_ioctl_req r{};
    r.pid = static_cast<uint32_t>(pid);
    return r;
}

CDriver::~CDriver() {
    close();
}

CDriver::CDriver(CDriver&& other) noexcept
    : m_fd(other.m_fd), m_targetPid(other.m_targetPid) {
    other.m_fd = -1;
    other.m_targetPid = 0;
}

CDriver& CDriver::operator=(CDriver&& other) noexcept {
    if (this != &other) {
        close();
        m_fd = other.m_fd;
        m_targetPid = other.m_targetPid;
        other.m_fd = -1;
        other.m_targetPid = 0;
    }
    return *this;
}

bool CDriver::open() {
    if (m_fd >= 0)
        return true;

    // Magic-handshake bootstrap: the kernel's __arm64_sys_reboot kprobe
    // pre-handler matches inner_regs[0]==MAGIC1 && inner_regs[1]==MAGIC2 and
    // writes the freshly-installed anon-inode fd into the userspace pointer
    // passed via inner_regs[3] (= the 4th reboot() arg). Both magics are the
    // same value per IDA dossier; regs[2] (the reboot `cmd` arg) is ignored.
    //
    // Reachability: works from adb shell uid. Bionic seccomp blocks
    // __NR_reboot for Zygote-forked app uids; if the client needs to run
    // inside an app, spawn it from adb shell or via a privileged helper.
    int newFd = -1;
    long rc = ::syscall(SYS_reboot, RebootMagic1, RebootMagic2, 0L, &newFd);
    int savedErrno = errno;
    if (newFd >= 0) {
        m_fd = newFd;
        return true;
    }
    (void)rc;
    errno = savedErrno;
    return false;
}

void CDriver::close() {
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
}

int CDriver::doIoctl(unsigned int cmd, drv_ioctl_req* req) {
    if (m_fd < 0 && !open())
        return -1;
    return ::ioctl(m_fd, cmd, req);
}

bool CDriver::readBytes(uint64_t addr, void* out, size_t len) {
    drv_ioctl_req req = makeReq(m_targetPid);
    req.addr = addr;
    req.buf = reinterpret_cast<uint64_t>(out);
    req.size = len;
    if (doIoctl(DRV_CMD_READ_MEM_LINEAR, &req) < 0)
        return false;
    return req.size == len;
}

bool CDriver::writeBytes(uint64_t addr, const void* in, size_t len) {
    drv_ioctl_req req = makeReq(m_targetPid);
    req.addr = addr;
    req.buf = reinterpret_cast<uint64_t>(in);
    req.size = len;
    if (doIoctl(DRV_CMD_WRITE_MEM_LINEAR, &req) < 0)
        return false;
    return req.size == len;
}

bool CDriver::readBytesVmap(uint64_t addr, void* out, size_t len) {
    drv_ioctl_req req = makeReq(m_targetPid);
    req.addr = addr;
    req.buf = reinterpret_cast<uint64_t>(out);
    req.size = len;
    if (doIoctl(DRV_CMD_READ_MEM_VMAP, &req) < 0)
        return false;
    return req.size == len;
}

bool CDriver::writeBytesVmap(uint64_t addr, const void* in, size_t len) {
    drv_ioctl_req req = makeReq(m_targetPid);
    req.addr = addr;
    req.buf = reinterpret_cast<uint64_t>(in);
    req.size = len;
    if (doIoctl(DRV_CMD_WRITE_MEM_VMAP, &req) < 0)
        return false;
    return req.size == len;
}

std::optional<uint64_t> CDriver::getModuleBase(const std::string& name) {
    drv_ioctl_req req = makeReq(m_targetPid);
    req.addr = reinterpret_cast<uint64_t>(name.c_str());
    if (doIoctl(DRV_CMD_GET_MODULE_BASE, &req) < 0)
        return std::nullopt;
    if (req.size == 0)
        return std::nullopt;
    return req.size;
}

std::optional<pid_t> CDriver::findTaskByComm(const std::string& comm) {
    drv_ioctl_req req = makeReq(0);
    req.addr = reinterpret_cast<uint64_t>(comm.c_str());
    if (doIoctl(DRV_CMD_FIND_TASK_BY_COMM, &req) < 0)
        return std::nullopt;
    if (req.size == 0 || req.size > 0x7fffffffULL)
        return std::nullopt;
    return static_cast<pid_t>(req.size);
}

std::optional<uint64_t> CDriver::getTls() {
    drv_ioctl_req req = makeReq(m_targetPid);
    if (doIoctl(DRV_CMD_GET_TLS, &req) < 0)
        return std::nullopt;
    if (req.size == 0)
        return std::nullopt;
    return req.size;
}

std::optional<uint64_t> CDriver::readVmaCookie(uint64_t addr) {
    drv_ioctl_req req = makeReq(m_targetPid);
    req.addr = addr;
    if (doIoctl(DRV_CMD_READ_VMA_COOKIE, &req) < 0)
        return std::nullopt;
    return req.size;
}

bool CDriver::hideKgsl() {
    char pidStr[32];
    std::snprintf(pidStr, sizeof(pidStr), "%d", static_cast<int>(m_targetPid));
    drv_ioctl_req req = makeReq(0);
    req.addr = reinterpret_cast<uint64_t>(pidStr);
    if (doIoctl(DRV_CMD_HIDE_KGSL, &req) < 0)
        return false;
    // Driver writes -EOPNOTSUPP cast to u64 into req.size when KGSL holder
    // offsets fail the kernel-pointer sanity check on the current build.
    return static_cast<int64_t>(req.size) >= 0;
}

std::vector<uint64_t> CDriver::multiRead(const std::vector<uint64_t>& addrs) {
    std::vector<uint64_t> out(addrs.size(), 0);
    if (addrs.empty())
        return out;

    // Driver ABI (do_memory_cmd case DRV_CMD_MULTI_READ):
    //   req.buf   = userspace pointer to drv_multi_read_req[] array
    //   req.extra = element count
    //   req.size writeback = 1 on success, 0 on failure
    // The parallel-u64[] shape we used previously sent the array via req.addr
    // and the count via req.size, both of which the driver ignores for this cmd.
    std::vector<drv_multi_read_req> descs(addrs.size());
    for (size_t i = 0; i < addrs.size(); ++i) {
        descs[i].user_dst = reinterpret_cast<uint64_t>(&out[i]);
        descs[i].src_va   = addrs[i];
        descs[i].len      = sizeof(uint64_t);
    }

    drv_ioctl_req req = makeReq(m_targetPid);
    req.buf   = reinterpret_cast<uint64_t>(descs.data());
    req.extra = descs.size();
    if (doIoctl(DRV_CMD_MULTI_READ, &req) < 0 || req.size != 1)
        out.clear();
    return out;
}

std::vector<VmaInfo> CDriver::dumpVmas() {
    std::vector<VmaInfo> entries(VmaDumpEntries);
    drv_ioctl_req req = makeReq(m_targetPid);
    req.buf = reinterpret_cast<uint64_t>(entries.data());
    req.size = entries.size() * sizeof(VmaInfo);
    if (doIoctl(DRV_CMD_DUMP_VMAS, &req) < 0) {
        entries.clear();
        return entries;
    }
    const size_t written = static_cast<size_t>(req.size) / sizeof(VmaInfo);
    entries.resize(written);
    return entries;
}

bool CDriver::installHooks() {
    drv_ioctl_req req = makeReq(0);
    return doIoctl(DRV_CMD_INSTALL_HOOKS, &req) >= 0;
}

bool CDriver::tearDown() {
    drv_ioctl_req req = makeReq(0);
    return doIoctl(DRV_CMD_TEAR_DOWN, &req) >= 0;
}

bool CDriver::installSigsegvSuppress() {
    drv_ioctl_req req = makeReq(0);
    return doIoctl(DRV_CMD_INSTALL_SIGSEGV_SUPPRESS, &req) >= 0;
}

bool CDriver::touchDown(int slot, int x, int y) {
    drv_touch_inject_req tr{};
    tr.slot_id = static_cast<uint32_t>(slot);
    tr.x = x;
    tr.y = y;
    drv_ioctl_req req = makeReq(0);
    req.addr = reinterpret_cast<uint64_t>(&tr);
    return doIoctl(DRV_CMD_TOUCH_DOWN, &req) >= 0;
}

bool CDriver::touchUp(int slot) {
    drv_touch_inject_req tr{};
    tr.slot_id = static_cast<uint32_t>(slot);
    drv_ioctl_req req = makeReq(0);
    req.addr = reinterpret_cast<uint64_t>(&tr);
    return doIoctl(DRV_CMD_TOUCH_UP, &req) >= 0;
}

bool CDriver::touchMove(int slot, int x, int y) {
    drv_touch_inject_req tr{};
    tr.slot_id = static_cast<uint32_t>(slot);
    tr.x = x;
    tr.y = y;
    drv_ioctl_req req = makeReq(0);
    req.addr = reinterpret_cast<uint64_t>(&tr);
    return doIoctl(DRV_CMD_TOUCH_MOVE, &req) >= 0;
}

// DRV_CMD_SENSOR_BIND(0x140) overloaded: pid==100 binds uprobe; else pushes gyro state.
bool CDriver::setGyroEnable(bool enable) {
    drv_ioctl_req req = makeReq(1);
    req.addr = enable ? 1 : 0;
    return doIoctl(DRV_CMD_SENSOR_BIND, &req) >= 0;
}

bool CDriver::setGyroDelta(float x, float y) {
    drv_ioctl_req req = makeReq(2);
    uint32_t xBits = 0;
    uint32_t yBits = 0;
    std::memcpy(&xBits, &x, sizeof(float));
    std::memcpy(&yBits, &y, sizeof(float));
    req.addr = xBits;
    req.buf = yBits;
    return doIoctl(DRV_CMD_SENSOR_BIND, &req) >= 0;
}

bool CDriver::bindSensorHook(uint64_t libOffset, int eventType) {
    drv_ioctl_req req = makeReq(100);
    req.addr = libOffset;
    req.size = static_cast<uint64_t>(eventType);
    return doIoctl(DRV_CMD_SENSOR_BIND, &req) >= 0;
}

CDriver driver;
