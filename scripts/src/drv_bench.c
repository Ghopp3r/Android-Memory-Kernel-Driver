// SPDX-License-Identifier: GPL-2.0
// Comparative read-latency benchmark: /proc/<pid>/mem vs process_vm_readv
// vs our driver's DRV_CMD_READ_MEM_LINEAR.
//
// Target: an arbitrary running process (default com.axlebolt.standoff2) and
// a loaded shared object inside it (default libunity.so).  Reads the first N
// bytes of the module's executable mapping via all three methods, in three
// sample sizes (16 B, 256 B, 4 KiB, 64 KiB, 1 MiB), N iterations per
// (method, size).  Reports median / p95 / p99 / min / max latency in ms and
// the implied steady-state throughput.
//
// Output:
//   - CSV  (method, size, iters, fails, median_ms, p95_ms, p99_ms, min_ms, max_ms, mb_s)
//   - JSON (same fields plus run metadata)
//   - stdout: human-readable per-(method,size) line.
//
// Usage:
//   drv_bench [--pkg=PKG] [--module=MOD] [--iters=N] [--csv=PATH] [--json=PATH]
#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "driver/uapi.h"

#define DEFAULT_PKG    "com.axlebolt.standoff2"
#define DEFAULT_MODULE "libunity.so"
#define MAX_SAMPLE_BYTES (1u << 20)   /* 1 MiB upper bound */

static int g_drv_fd = -1;

/* ----------------------- timing helpers ----------------------- */
static double ts_diff_ms(struct timespec a, struct timespec b) {
	return (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
}
static int dbl_cmp(const void *a, const void *b) {
	double da = *(const double *)a, db = *(const double *)b;
	return (da > db) - (da < db);
}

/* ----------------------- driver open (reboot handshake) ----------------------- */
static bool driver_open(void) {
	int fd = -1;
	(void)syscall(SYS_reboot, (long)DRIVER_REBOOT_MAGIC1,
	              (long)DRIVER_REBOOT_MAGIC2, 0L, (long)&fd);
	if (fd < 0) {
		fprintf(stderr, "driver_open: reboot handshake failed (%s)\n", strerror(errno));
		return false;
	}
	g_drv_fd = fd;
	return true;
}

/* ----------------------- target resolution ----------------------- */
/* Find first pid whose /proc/<pid>/cmdline starts with `pkg`. */
static pid_t find_pid_by_pkg(const char *pkg) {
	DIR *d = opendir("/proc");
	if (!d) return 0;
	size_t plen = strlen(pkg);
	pid_t found = 0;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
		char path[64], buf[256] = {0};
		snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
		int fd = open(path, O_RDONLY);
		if (fd < 0) continue;
		ssize_t r = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (r <= 0) continue;
		if (strncmp(buf, pkg, plen) == 0) {
			found = (pid_t)atoi(e->d_name);
			break;
		}
	}
	closedir(d);
	return found;
}

/* Walk /proc/<pid>/maps; return the base address of the first r-x mapping
 * whose pathname contains `module`. */
static uint64_t find_module_base(pid_t pid, const char *module) {
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	uint64_t base = 0;
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		/* Format: start-end perms pgoff dev inode path */
		unsigned long start, end, pgoff;
		char perms[8] = {0}, p[256] = {0};
		int parsed = sscanf(line, "%lx-%lx %4s %lx %*s %*s %255s",
		                    &start, &end, perms, &pgoff, p);
		if (parsed < 5) continue;
		if (perms[0] != 'r') continue;
		if (!strstr(p, module)) continue;
		base = (uint64_t)start;
		break;
	}
	fclose(f);
	return base;
}

/* ----------------------- the three read methods ----------------------- */

static int g_procmem_fd = -1;
static pid_t g_procmem_pid = 0;

static int read_via_procmem(pid_t pid, uint64_t addr, void *buf, size_t len) {
	if (g_procmem_fd < 0 || g_procmem_pid != pid) {
		if (g_procmem_fd >= 0) close(g_procmem_fd);
		char path[64];
		snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
		g_procmem_fd = open(path, O_RDONLY | O_LARGEFILE);
		g_procmem_pid = pid;
		if (g_procmem_fd < 0) return -errno;
	}
	ssize_t n = pread64(g_procmem_fd, buf, len, (off_t)addr);
	return (n == (ssize_t)len) ? 0 : (n < 0 ? -errno : -EIO);
}

static int read_via_vmread(pid_t pid, uint64_t addr, void *buf, size_t len) {
	struct iovec local  = { .iov_base = buf,                     .iov_len = len };
	struct iovec remote = { .iov_base = (void *)(uintptr_t)addr, .iov_len = len };
	ssize_t n = syscall(SYS_process_vm_readv, (long)pid, &local, 1L, &remote, 1L, 0L);
	return (n == (ssize_t)len) ? 0 : (n < 0 ? -errno : -EIO);
}

static int read_via_driver(pid_t pid, uint64_t addr, void *buf, size_t len) {
	struct drv_ioctl_req r = {0};
	r.pid  = (uint64_t)(uint32_t)pid;
	r.addr = addr;
	r.buf  = (uintptr_t)buf;
	r.size = len;
	if (ioctl(g_drv_fd, DRV_CMD_READ_MEM_LINEAR, &r) < 0)
		return -errno;
	return (r.size == len) ? 0 : -EIO;
}

/* ----------------------- benchmark loop ----------------------- */

struct row {
	const char *method;
	size_t size;
	int iters;
	int fails;
	double median_ms, p95_ms, p99_ms, min_ms, max_ms, mb_s;
};

static void bench(pid_t pid, uint64_t addr, const char *method_name,
                  int (*fn)(pid_t, uint64_t, void *, size_t),
                  size_t size, int iters,
                  struct row *out, uint8_t *scratch) {
	double *samples = calloc((size_t)iters, sizeof(double));

	/* Warmup so TLB / fd-state settles. */
	for (int i = 0; i < 10; ++i)
		(void)fn(pid, addr, scratch, size);

	int fails = 0;
	for (int i = 0; i < iters; ++i) {
		struct timespec t0, t1;
		clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
		int rc = fn(pid, addr, scratch, size);
		clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
		samples[i] = ts_diff_ms(t0, t1);
		if (rc) ++fails;
	}

	qsort(samples, (size_t)iters, sizeof(double), dbl_cmp);
	double med = samples[iters / 2];
	double p95 = samples[(int)(iters * 0.95)];
	double p99 = samples[(int)(iters * 0.99)];
	double mn  = samples[0];
	double mx  = samples[iters - 1];

	double mb_s = (med > 0.0) ? (double)size / (med * 1024.0) : 0.0;

	out->method    = method_name;
	out->size      = size;
	out->iters     = iters;
	out->fails     = fails;
	out->median_ms = med;
	out->p95_ms    = p95;
	out->p99_ms    = p99;
	out->min_ms    = mn;
	out->max_ms    = mx;
	out->mb_s      = mb_s;

	printf("  %-18s size=%-7zu n=%d fails=%-2d  med=%8.4f  p95=%8.4f  p99=%8.4f  min=%8.4f  max=%8.4f  %8.2f MB/s\n",
	       method_name, size, iters, fails, med, p95, p99, mn, mx, mb_s);

	free(samples);
}

/* ----------------------- main ----------------------- */

int main(int argc, char **argv) {
	const char *pkg = DEFAULT_PKG;
	const char *mod = DEFAULT_MODULE;
	int iters = 1000;
	const char *csv_path  = "/data/local/tmp/test/bench.csv";
	const char *json_path = "/data/local/tmp/test/bench.json";

	for (int i = 1; i < argc; ++i) {
		if (!strncmp(argv[i], "--pkg=", 6))         pkg = argv[i] + 6;
		else if (!strncmp(argv[i], "--module=", 9)) mod = argv[i] + 9;
		else if (!strncmp(argv[i], "--iters=", 8))  iters = atoi(argv[i] + 8);
		else if (!strncmp(argv[i], "--csv=", 6))    csv_path = argv[i] + 6;
		else if (!strncmp(argv[i], "--json=", 7))   json_path = argv[i] + 7;
		else {
			fprintf(stderr, "drv_bench: unknown arg %s\n", argv[i]);
			return 2;
		}
	}

	pid_t pid = find_pid_by_pkg(pkg);
	if (pid <= 0) {
		fprintf(stderr, "drv_bench: package '%s' not running\n", pkg);
		return 1;
	}
	uint64_t base = find_module_base(pid, mod);
	if (!base) {
		fprintf(stderr, "drv_bench: module '%s' not found in pid %d\n", mod, (int)pid);
		return 1;
	}
	if (!driver_open()) return 3;

	printf("== target: %s pid=%d %s base=0x%lx ==\n",
	       pkg, (int)pid, mod, (unsigned long)base);
	printf("== driver fd=%d  iters=%d  csv=%s  json=%s ==\n",
	       g_drv_fd, iters, csv_path, json_path);

	uint8_t *scratch = malloc(MAX_SAMPLE_BYTES);
	if (!scratch) { perror("malloc scratch"); return 4; }

	FILE *csv = fopen(csv_path, "w");
	if (!csv) { perror(csv_path); return 4; }
	fprintf(csv, "method,size,iters,fails,median_ms,p95_ms,p99_ms,min_ms,max_ms,throughput_mb_s\n");

	FILE *js = fopen(json_path, "w");
	if (!js) { perror(json_path); return 4; }
	fprintf(js, "{\n  \"target\": { \"pkg\": \"%s\", \"pid\": %d, \"module\": \"%s\", \"base\": \"0x%lx\" },\n",
	        pkg, (int)pid, mod, (unsigned long)base);
	fprintf(js, "  \"iters\": %d,\n  \"rows\": [\n", iters);
	bool first = true;

	const size_t sizes[] = { 16, 256, 4096, 65536, 1u << 20 };
	const size_t nsizes  = sizeof(sizes) / sizeof(sizes[0]);

	struct { const char *name; int (*fn)(pid_t, uint64_t, void *, size_t); } methods[] = {
		{ "procmem",          read_via_procmem },
		{ "process_vm_readv", read_via_vmread  },
		{ "driver",           read_via_driver  },
	};

	for (size_t s = 0; s < nsizes; ++s) {
		printf("\n-- size %zu B --\n", sizes[s]);
		for (size_t m = 0; m < sizeof(methods) / sizeof(methods[0]); ++m) {
			struct row r = {0};
			bench(pid, base, methods[m].name, methods[m].fn, sizes[s], iters, &r, scratch);

			fprintf(csv, "%s,%zu,%d,%d,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
			        r.method, r.size, r.iters, r.fails,
			        r.median_ms, r.p95_ms, r.p99_ms, r.min_ms, r.max_ms, r.mb_s);

			if (!first) fputs(",\n", js);
			first = false;
			fprintf(js, "    { \"method\": \"%s\", \"size\": %zu, \"iters\": %d, \"fails\": %d,"
			        " \"median_ms\": %.4f, \"p95_ms\": %.4f, \"p99_ms\": %.4f,"
			        " \"min_ms\": %.4f, \"max_ms\": %.4f, \"throughput_mb_s\": %.4f }",
			        r.method, r.size, r.iters, r.fails,
			        r.median_ms, r.p95_ms, r.p99_ms, r.min_ms, r.max_ms, r.mb_s);
		}
	}

	fprintf(js, "\n  ]\n}\n");
	fclose(js);
	fclose(csv);
	free(scratch);
	if (g_procmem_fd >= 0) close(g_procmem_fd);
	if (g_drv_fd >= 0)     close(g_drv_fd);
	printf("\nCSV  -> %s\nJSON -> %s\n", csv_path, json_path);
	return 0;
}
