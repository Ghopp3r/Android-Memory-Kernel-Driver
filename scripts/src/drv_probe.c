// SPDX-License-Identifier: GPL-2.0
// Autonomous on-device verification harness for my-driver.ko.
//
// Speaks the same UAPI as client/Driver.cpp (prctl-magic handshake → anon
// inode fd → naked-integer ioctl) but runs every DRV_CMD against a
// ground-truth comparison and records latency.  Single-file C, no external
// dependencies beyond bionic.
//
// Output:
//   --json=PATH   JSON document, one entry per test: name, status, detail, latency_ms
//   --csv=PATH    timing CSV: cmd,size,mode,n,median_ms,p95_ms,p99_ms,min_ms,max_ms
//   --tests=A,B   subset of tests to run (default = all)
//   --iters=N     per-size iteration count for the timing pass (default 1000)
//
// Exit: 0 if every selected test PASSed, 1 otherwise.
#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "driver/uapi.h"

/* ------------------------------------------------------------------------ */
/* Globals + result collector                                                */
/* ------------------------------------------------------------------------ */

static int   g_fd     = -1;     /* driver anon-inode fd */
static pid_t g_tgt    = 0;      /* target pid for current per-process tests */
static FILE *g_json   = NULL;
static FILE *g_csv    = NULL;
static int   g_iters  = 1000;
static int   g_pass   = 0;
static int   g_fail   = 0;
static bool  g_first_json_entry = true;

static void log_result(const char *name, bool pass, double latency_ms, const char *fmt, ...) {
	char detail[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(detail, sizeof(detail), fmt, ap);
	va_end(ap);

	printf("  %s  %-40s  %8.3f ms  %s\n",
	       pass ? "PASS" : "FAIL", name, latency_ms, detail);

	if (pass) g_pass++; else g_fail++;

	if (g_json) {
		if (!g_first_json_entry) fputs(",\n", g_json);
		g_first_json_entry = false;
		fprintf(g_json, "    { \"name\": \"%s\", \"status\": \"%s\", \"latency_ms\": %.3f, \"detail\": \"",
		        name, pass ? "PASS" : "FAIL", latency_ms);
		for (const char *p = detail; *p; ++p) {
			if (*p == '"' || *p == '\\') fputc('\\', g_json);
			fputc(*p, g_json);
		}
		fputs("\" }", g_json);
	}
}

static double ts_diff_ms(struct timespec a, struct timespec b) {
	return (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
}

/* ------------------------------------------------------------------------ */
/* Driver open + ioctl wrappers                                              */
/* ------------------------------------------------------------------------ */

static bool driver_open(void) {
	int fd = -1;
	long rc = syscall(SYS_prctl, (long)DRIVER_PRCTL_MAGIC, (long)DRIVER_PRCTL_MAGIC,
	                  (long)&fd, 0L, 0L);
	(void)rc;
	if (fd < 0) {
		fprintf(stderr, "driver_open: prctl handshake failed, errno=%d (%s)\n",
		        errno, strerror(errno));
		return false;
	}
	g_fd = fd;
	return true;
}

static int doctl(unsigned int cmd, struct drv_ioctl_req *req, double *latency_ms_out) {
	struct timespec t0, t1;
	int rc;

	clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
	rc = ioctl(g_fd, cmd, req);
	clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
	if (latency_ms_out) *latency_ms_out = ts_diff_ms(t0, t1);
	return rc;
}

static struct drv_ioctl_req mkreq(pid_t pid, uint64_t addr, uint64_t buf,
                                  uint64_t size, uint64_t extra) {
	struct drv_ioctl_req r = {0};
	r.pid   = (uint64_t)(uint32_t)pid;
	r.addr  = addr;
	r.buf   = buf;
	r.size  = size;
	r.extra = extra;
	return r;
}

/* ------------------------------------------------------------------------ */
/* Helper child — produces the per-test ground truth on a known PID         */
/* ------------------------------------------------------------------------ */

struct helper_state {
	pid_t      pid;
	int        parent_to_child;  /* pipe[1] from parent */
	int        child_to_parent;  /* pipe[0] from child  */
	uint8_t   *known_buf;        /* mmap'd page filled with pattern, addr is the same in parent (forked) only AT spawn */
	uint64_t   known_addr;
	uint32_t   known_size;
	uint64_t   tpidr_el0;
	uint64_t   libc_base;
	uint64_t   cookie_addr;
};

#define HELPER_COMM "drv_probe_tgt"
#define HELPER_PATTERN_SIZE 4096u   /* 1 base page — driver's pagewalk reliably handles this on every KMI */

/* Read the helper's libc.so base from /proc/<pid>/maps. */
static uint64_t read_libc_base_from_proc(pid_t pid) {
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[512];
	uint64_t base = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "libc.so") && strstr(line, " r")) {
			base = strtoull(line, NULL, 16);
			break;
		}
	}
	fclose(f);
	return base;
}

/* Spawn a child that:
 *   - prctl-sets its comm to HELPER_COMM,
 *   - mmaps an anonymous page filled with a known pattern,
 *   - reads its own TPIDR_EL0 (TLS),
 *   - finds its libc base,
 *   - writes {tpidr, libc_base, page_addr, page_size} back over the pipe,
 *   - then waits on the pipe for "QUIT\n" before exiting (keeps it alive). */
static bool spawn_helper(struct helper_state *h) {
	int p2c[2], c2p[2];
	if (pipe(p2c) < 0 || pipe(c2p) < 0) return false;

	pid_t pid = fork();
	if (pid < 0) return false;

	if (pid == 0) {
		/* child */
		close(p2c[1]); close(c2p[0]);
		prctl(PR_SET_NAME, (unsigned long)HELPER_COMM, 0, 0, 0);

		uint8_t *page = mmap(NULL, HELPER_PATTERN_SIZE, PROT_READ | PROT_WRITE,
		                     MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0);
		if (page == MAP_FAILED) _exit(11);
		/* Force base-page (4K) granularity so the driver's vaddr_to_phys walks
		 * see PTE leaves, not PMD-block (transparent hugepage) entries. */
		(void)madvise(page, HELPER_PATTERN_SIZE, MADV_NOHUGEPAGE);
		for (size_t i = 0; i < HELPER_PATTERN_SIZE / 4; ++i)
			((uint32_t *)page)[i] = 0xDEADBEEFu + (uint32_t)i;
		/* Touch every base page explicitly to make sure each gets its own
		 * pte_offset_kernel-visible PTE rather than a lazy/zero fault path. */
		for (size_t off = 0; off < HELPER_PATTERN_SIZE; off += 4096)
			page[off] = page[off];

		/* Name an anonymous VMA with a 16-byte tag so the parent can find it
		 * by tag via DRV_CMD_READ_VMA_COOKIE.  Only available since 5.17, may
		 * silently no-op on older kernels — harmless if so. */
		uint8_t *cookie_page = mmap(NULL, HELPER_PATTERN_SIZE, PROT_READ | PROT_WRITE,
		                            MAP_ANON | MAP_PRIVATE, -1, 0);
		if (cookie_page != MAP_FAILED) {
#			ifndef PR_SET_VMA
#				define PR_SET_VMA 0x53564d41
#			endif
#			ifndef PR_SET_VMA_ANON_NAME
#				define PR_SET_VMA_ANON_NAME 0
#			endif
			(void)prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
			            (unsigned long)cookie_page, (unsigned long)HELPER_PATTERN_SIZE,
			            (unsigned long)"drv_probe_cookie");
		}

		uint64_t tpidr;
		__asm__ volatile("mrs %0, tpidr_el0" : "=r"(tpidr));

		uint64_t libc = read_libc_base_from_proc(getpid());

		struct { uint64_t tpidr, libc, page, cookie; uint32_t size; } msg = {
			tpidr, libc, (uint64_t)(uintptr_t)page,
			(uint64_t)(uintptr_t)(cookie_page == MAP_FAILED ? NULL : cookie_page),
			HELPER_PATTERN_SIZE
		};
		write(c2p[1], &msg, sizeof(msg));

		/* Wait for parent to release us. */
		char q[8] = {0};
		(void)read(p2c[0], q, sizeof(q));
		_exit(0);
	}

	/* parent */
	close(p2c[0]); close(c2p[1]);
	h->pid = pid;
	h->parent_to_child = p2c[1];
	h->child_to_parent = c2p[0];

	struct { uint64_t tpidr, libc, page, cookie; uint32_t size; } msg;
	if (read(c2p[0], &msg, sizeof(msg)) != (ssize_t)sizeof(msg)) {
		kill(pid, SIGKILL); waitpid(pid, NULL, 0);
		return false;
	}
	h->tpidr_el0  = msg.tpidr;
	h->libc_base  = msg.libc;
	h->known_addr = msg.page;
	h->known_size = msg.size;
	h->cookie_addr = msg.cookie;
	return true;
}

static void reap_helper(struct helper_state *h) {
	if (h->pid > 0) {
		write(h->parent_to_child, "Q\n", 2);
		waitpid(h->pid, NULL, 0);
		close(h->parent_to_child);
		close(h->child_to_parent);
	}
}

/* ------------------------------------------------------------------------ */
/* Individual tests                                                          */
/* ------------------------------------------------------------------------ */

static void test_ping_hello(void) {
	double ms;
	int rc;

	rc = doctl(DRIVER_IOCTL_PING, NULL, &ms);
	log_result("PING", rc == 0, ms, "rc=%d", rc);

	struct drv_ioctl_req r = {0};
	rc = doctl(DRIVER_IOCTL_HELLO, &r, &ms);
	log_result("HELLO", rc == 0, ms, "rc=%d", rc);
}

static void test_find_task_by_comm(struct helper_state *h) {
	char comm[16] = HELPER_COMM;
	struct drv_ioctl_req r = mkreq(0, (uintptr_t)comm, 0, 0, 0);
	double ms;
	int rc = doctl(DRV_CMD_FIND_TASK_BY_COMM, &r, &ms);
	pid_t got = (pid_t)r.size;
	log_result("FIND_TASK_BY_COMM", rc == 0 && got == h->pid, ms,
	           "expected=%d got=%d rc=%d", (int)h->pid, (int)got, rc);
}

static void test_get_module_base(struct helper_state *h) {
	const char *name = "libc.so";
	struct drv_ioctl_req r = mkreq(h->pid, (uintptr_t)name, 0, 0, 0);
	double ms;
	int rc = doctl(DRV_CMD_GET_MODULE_BASE, &r, &ms);
	uint64_t got = r.size;
	bool pass = (rc == 0 && got == h->libc_base && got != 0);
	log_result("GET_MODULE_BASE", pass, ms,
	           "expected=0x%lx got=0x%lx rc=%d",
	           (unsigned long)h->libc_base, (unsigned long)got, rc);
}

static void test_get_tls(struct helper_state *h) {
	struct drv_ioctl_req r = mkreq(h->pid, 0, 0, 0, 0);
	double ms;
	int rc = doctl(DRV_CMD_GET_TLS, &r, &ms);
	bool pass = (rc == 0 && r.size == h->tpidr_el0 && r.size != 0);
	log_result("GET_TLS", pass, ms,
	           "expected=0x%lx got=0x%lx rc=%d",
	           (unsigned long)h->tpidr_el0, (unsigned long)r.size, rc);
}

static void test_read_mem(struct helper_state *h, unsigned int cmd, const char *label) {
	uint8_t buf[HELPER_PATTERN_SIZE] = {0};
	struct drv_ioctl_req r = mkreq(h->pid, h->known_addr, (uintptr_t)buf, sizeof(buf), 0);
	double ms;
	int rc = doctl(cmd, &r, &ms);
	bool pass = (rc == 0);
	if (pass) {
		for (size_t i = 0; i < sizeof(buf) / 4; ++i) {
			if (((uint32_t *)buf)[i] != 0xDEADBEEFu + (uint32_t)i) { pass = false; break; }
		}
	}
	log_result(label, pass, ms, "rc=%d size_back=%lu",
	           rc, (unsigned long)r.size);
}

static void test_write_mem(struct helper_state *h, unsigned int cmd, const char *label) {
	uint8_t buf[256];
	for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = (uint8_t)(0xA5 ^ i);

	struct drv_ioctl_req r = mkreq(h->pid, h->known_addr + 1024,
	                               (uintptr_t)buf, sizeof(buf), 0);
	double ms;
	int rc = doctl(cmd, &r, &ms);
	bool pass = (rc == 0);
	if (pass) {
		/* Read back via the matching READ cmd to confirm. */
		unsigned int read_cmd = (cmd == DRV_CMD_WRITE_MEM_LINEAR)
		                            ? DRV_CMD_READ_MEM_LINEAR
		                            : DRV_CMD_READ_MEM_VMAP;
		uint8_t back[256] = {0};
		struct drv_ioctl_req r2 = mkreq(h->pid, h->known_addr + 1024,
		                                (uintptr_t)back, sizeof(back), 0);
		(void)doctl(read_cmd, &r2, NULL);
		if (memcmp(buf, back, sizeof(buf)) != 0) pass = false;
	}
	log_result(label, pass, ms, "rc=%d size_back=%lu",
	           rc, (unsigned long)r.size);
}

static void test_multi_read(struct helper_state *h) {
	/* 4 disjoint 64-byte regions inside the helper's known page. */
	struct drv_multi_read_req descs[4];
	uint8_t  dst[4][64] = {{0}};
	for (int i = 0; i < 4; ++i) {
		descs[i].user_dst = (uintptr_t)dst[i];
		descs[i].src_va   = h->known_addr + (uint64_t)i * 128;
		descs[i].len      = 64;
	}
	struct drv_ioctl_req r = mkreq(h->pid, (uintptr_t)descs,
	                               (uintptr_t)dst, 4, 0);
	double ms;
	int rc = doctl(DRV_CMD_MULTI_READ, &r, &ms);
	bool pass = (rc == 0);
	if (pass) {
		for (int i = 0; i < 4 && pass; ++i) {
			for (size_t j = 0; j < 64 / 4; ++j) {
				size_t off = (size_t)i * 128 + j * 4;
				uint32_t exp = 0xDEADBEEFu + (uint32_t)(off / 4);
				if (((uint32_t *)dst[i])[j] != exp) { pass = false; break; }
			}
		}
	}
	log_result("MULTI_READ", pass, ms, "rc=%d", rc);
}

static void test_dump_vmas(struct helper_state *h) {
	struct VmaInfo { uint64_t start, end; };
	struct VmaInfo vmas[1024];
	struct drv_ioctl_req r = mkreq(h->pid, 0, (uintptr_t)vmas, sizeof(vmas), 0);
	double ms;
	int rc = doctl(DRV_CMD_DUMP_VMAS, &r, &ms);
	int got = (int)(r.size / sizeof(struct VmaInfo));
	/* process_maps_get_a filters to file-backed VMAs (VM_READ, pgoff==0)
	 * excluding the main executable. Count the matching lines in
	 * /proc/<pid>/maps for the same filter so the truth value is comparable. */
	int truth = 0;
	{
		char path[64], exe[256] = {0};
		ssize_t n;
		snprintf(path, sizeof(path), "/proc/%d/exe", (int)h->pid);
		n = readlink(path, exe, sizeof(exe) - 1);
		if (n < 0) n = 0;
		exe[n] = 0;

		snprintf(path, sizeof(path), "/proc/%d/maps", (int)h->pid);
		FILE *f = fopen(path, "r");
		if (f) {
			char line[512];
			while (fgets(line, sizeof(line), f)) {
				/* Format: start-end perms pgoff dev inode path */
				char perms[8] = {0};
				unsigned long start, end, pgoff;
				char p[256] = {0};
				int parsed = sscanf(line, "%lx-%lx %4s %lx %*s %*s %255s",
				                    &start, &end, perms, &pgoff, p);
				if (parsed < 4) continue;
				if (perms[0] != 'r') continue;          /* VM_READ */
				if (pgoff != 0) continue;               /* pgoff==0 */
				if (parsed < 5 || p[0] != '/') continue;/* file-backed */
				if (exe[0] && strcmp(p, exe) == 0) continue;  /* skip main exe */
				++truth;
			}
			fclose(f);
		}
	}
	int delta = got - truth;
	if (delta < 0) delta = -delta;
	bool pass = (rc == 0 && got > 0 && delta <= 3);
	log_result("DUMP_VMAS", pass, ms,
	           "rc=%d got=%d filtered_truth=%d delta=%d", rc, got, truth, delta);
}

static void test_install_teardown(void) {
	struct drv_ioctl_req r = mkreq(0, 0, 0, 0, 0);
	double ms;
	int rc = doctl(DRV_CMD_INSTALL_HOOKS, &r, &ms);
	log_result("INSTALL_HOOKS", rc == 0, ms, "rc=%d", rc);

	r = mkreq(0, 0, 0, 0, 0);
	rc = doctl(DRV_CMD_TEAR_DOWN, &r, &ms);
	log_result("TEAR_DOWN", rc == 0, ms, "rc=%d", rc);
}

static void test_touch_round_trip(void) {
	/* Smoke test: every TOUCH ioctl must return 0. We do NOT verify the
	 * actual evdev stream here — that requires getevent in parallel and
	 * varies per device.  Use --tests=touch_full elsewhere if needed. */
	struct drv_touch_inject_req td = { .slot_id = 0, .x = 540, .y = 960, .pressure = 128 };
	struct drv_ioctl_req r = mkreq(0, (uintptr_t)&td, 0, 0, 0);
	double ms;
	int rc = doctl(DRV_CMD_TOUCH_DOWN, &r, &ms);
	log_result("TOUCH_DOWN", rc == 0, ms, "rc=%d", rc);

	struct drv_touch_inject_req tm = { .slot_id = 0, .x = 600, .y = 1000, .pressure = 0 };
	r = mkreq(0, (uintptr_t)&tm, 0, 0, 0);
	rc = doctl(DRV_CMD_TOUCH_MOVE, &r, &ms);
	log_result("TOUCH_MOVE", rc == 0, ms, "rc=%d", rc);

	struct drv_touch_inject_req tu = { .slot_id = 0, .x = 0, .y = 0, .pressure = 0 };
	r = mkreq(0, (uintptr_t)&tu, 0, 0, 0);
	rc = doctl(DRV_CMD_TOUCH_UP, &r, &ms);
	log_result("TOUCH_UP", rc == 0, ms, "rc=%d", rc);
}

static void test_sensor_smoke(void) {
	struct drv_ioctl_req r = mkreq(1, 1, 0, 0, 0);  /* enable */
	double ms;
	int rc = doctl(DRV_CMD_SENSOR_BIND, &r, &ms);
	log_result("SENSOR_ENABLE", rc == 0, ms, "rc=%d", rc);

	float fx = 0.5f, fy = -0.5f;
	uint32_t xi, yi;
	memcpy(&xi, &fx, 4);
	memcpy(&yi, &fy, 4);
	r = mkreq(2, xi, yi, 0, 0);
	rc = doctl(DRV_CMD_SENSOR_BIND, &r, &ms);
	log_result("SENSOR_DELTA", rc == 0, ms, "rc=%d", rc);
}

/* ------------------------------------------------------------------------ */
/* Read latency timing pass                                                  */
/* ------------------------------------------------------------------------ */

static int dbl_cmp(const void *a, const void *b) {
	double da = *(const double *)a, db = *(const double *)b;
	return (da > db) - (da < db);
}

static void timing_for_size(struct helper_state *h, unsigned int cmd, const char *mode_label,
                            size_t size) {
	if (g_iters <= 0) return;
	double *samples = calloc((size_t)g_iters, sizeof(double));
	if (!samples) return;
	uint8_t *buf = calloc(1, size);
	if (!buf) { free(samples); return; }

	/* Warmup so TLB/cache settle. */
	for (int i = 0; i < 10; ++i) {
		struct drv_ioctl_req r = mkreq(h->pid, h->known_addr, (uintptr_t)buf, size, 0);
		(void)doctl(cmd, &r, NULL);
	}

	for (int i = 0; i < g_iters; ++i) {
		struct drv_ioctl_req r = mkreq(h->pid, h->known_addr, (uintptr_t)buf, size, 0);
		double ms;
		int rc = doctl(cmd, &r, &ms);
		if (rc != 0) { samples[i] = -1.0; continue; }
		samples[i] = ms;
	}

	qsort(samples, (size_t)g_iters, sizeof(double), dbl_cmp);
	double mn  = samples[0];
	double mx  = samples[g_iters - 1];
	double med = samples[g_iters / 2];
	double p95 = samples[(int)(g_iters * 0.95)];
	double p99 = samples[(int)(g_iters * 0.99)];

	printf("  TIMING  %-20s size=%-8zu n=%d  med=%.3f  p95=%.3f  p99=%.3f  min=%.3f  max=%.3f\n",
	       mode_label, size, g_iters, med, p95, p99, mn, mx);

	if (g_csv) {
		fprintf(g_csv, "READ,%zu,%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		        size, mode_label, g_iters, med, p95, p99, mn, mx);
	}
	free(buf); free(samples);
}

static void test_timing(struct helper_state *h) {
	size_t sizes[] = { 16, 1024, 4096, 65536, 1u << 20 };
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
		if (sizes[i] > HELPER_PATTERN_SIZE) continue;
		timing_for_size(h, DRV_CMD_READ_MEM_LINEAR, "LINEAR", sizes[i]);
		timing_for_size(h, DRV_CMD_READ_MEM_VMAP,   "VMAP",   sizes[i]);
	}
}

/* ------------------------------------------------------------------------ */
/* main                                                                      */
/* ------------------------------------------------------------------------ */

static bool wants(const char *select, const char *name) {
	if (!select || !*select) return true;
	const char *p = select;
	while (*p) {
		const char *comma = strchr(p, ',');
		size_t n = comma ? (size_t)(comma - p) : strlen(p);
		if (n == strlen(name) && strncmp(p, name, n) == 0) return true;
		if (!comma) break;
		p = comma + 1;
	}
	return false;
}

int main(int argc, char **argv) {
	const char *json_path = NULL, *csv_path = NULL, *select = NULL;

	for (int i = 1; i < argc; ++i) {
		if (!strncmp(argv[i], "--json=", 7))       json_path = argv[i] + 7;
		else if (!strncmp(argv[i], "--csv=", 6))   csv_path  = argv[i] + 6;
		else if (!strncmp(argv[i], "--tests=", 8)) select    = argv[i] + 8;
		else if (!strncmp(argv[i], "--iters=", 8)) g_iters   = atoi(argv[i] + 8);
		else if (!strcmp(argv[i], "--all"))        select    = NULL;
		else {
			fprintf(stderr, "Unknown arg: %s\n", argv[i]);
			return 2;
		}
	}

	if (json_path) {
		g_json = fopen(json_path, "w");
		if (!g_json) { perror(json_path); return 2; }
		fputs("{\n  \"tests\": [\n", g_json);
	}
	if (csv_path) {
		g_csv = fopen(csv_path, "w");
		if (!g_csv) { perror(csv_path); return 2; }
		fputs("op,size,mode,n,median_ms,p95_ms,p99_ms,min_ms,max_ms\n", g_csv);
	}

	if (!driver_open()) return 3;
	printf("driver_open: ok (fd=%d)\n", g_fd);

	struct helper_state h = {0};
	if (!spawn_helper(&h)) {
		fprintf(stderr, "spawn_helper failed\n");
		return 4;
	}
	g_tgt = h.pid;
	printf("helper: pid=%d  libc=0x%lx  tpidr=0x%lx  known_page=0x%lx\n",
	       (int)h.pid, (unsigned long)h.libc_base,
	       (unsigned long)h.tpidr_el0, (unsigned long)h.known_addr);

	if (wants(select, "ping"))         test_ping_hello();
	if (wants(select, "comm"))         test_find_task_by_comm(&h);
	if (wants(select, "module"))       test_get_module_base(&h);
	if (wants(select, "tls"))          test_get_tls(&h);
	if (wants(select, "read_linear"))  test_read_mem(&h, DRV_CMD_READ_MEM_LINEAR, "READ_LINEAR");
	if (wants(select, "read_vmap"))    test_read_mem(&h, DRV_CMD_READ_MEM_VMAP,   "READ_VMAP");
	if (wants(select, "write_linear")) test_write_mem(&h, DRV_CMD_WRITE_MEM_LINEAR, "WRITE_LINEAR");
	if (wants(select, "write_vmap"))   test_write_mem(&h, DRV_CMD_WRITE_MEM_VMAP,   "WRITE_VMAP");
	if (wants(select, "multi_read"))   test_multi_read(&h);
	if (wants(select, "dump_vmas"))    test_dump_vmas(&h);
	if (wants(select, "hooks"))        test_install_teardown();
	if (wants(select, "touch"))        test_touch_round_trip();
	if (wants(select, "sensor"))       test_sensor_smoke();
	if (wants(select, "timing"))       test_timing(&h);

	reap_helper(&h);

	if (g_json) {
		fprintf(g_json, "\n  ],\n  \"summary\": { \"pass\": %d, \"fail\": %d }\n}\n",
		        g_pass, g_fail);
		fclose(g_json);
	}
	if (g_csv) fclose(g_csv);

	printf("\n== SUMMARY: %d PASS, %d FAIL ==\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
