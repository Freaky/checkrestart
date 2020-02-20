
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <libprocstat.h>
#include <signal.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>

static int needheader = 1;
static int binonly = 0;

static int
getprocstr(pid_t pid, int node, char *str, size_t maxlen) {
	size_t len = maxlen;
	int name[4] = { CTL_KERN, KERN_PROC, node, pid };
	str[0] = '\0';
	int error = sysctl(name, nitems(name), str, &len, NULL, 0);
	if (error != 0) return errno;
	else return 0;
}

static int
getpathname(pid_t pid, char *pathname, size_t maxlen) {
	return getprocstr(pid, KERN_PROC_PATHNAME, pathname, maxlen);
}

static int
getargs(pid_t pid, char *args, size_t maxlen) {
	return getprocstr(pid, KERN_PROC_ARGS, args, maxlen);
}

static void
needsrestart(const struct kinfo_proc *proc, const char *why, const char *note) {
	if (needheader) {
		needheader = 0;
		printf("%5s %5s %16s %7s %s\n", "PID", "JID", "PROCESS", "UPDATED", "COMMAND");
	}
	printf("%5d %5d %16s %7s %s\n", proc->ki_pid, proc->ki_jid, proc->ki_comm, why, note);
}

static void
usage(void) {
	printf("usage: checkrestart [-Hb] [pid [pid ...]]\n");
	exit(1);
}

static void
checkrestart(struct procstat *prstat, struct kinfo_proc *proc) {
	char pathname[PATH_MAX];

	// Skip kernel processes
	if (proc->ki_ppid == 0) return;

	int error = getpathname(proc->ki_pid, pathname, sizeof(pathname));
	if (error != 0 && error != ENOENT) return;
	if (error == ENOENT) {
		// Verify ENOENT isn't down to the process going away
		if (kill(proc->ki_pid, 0) == -1 && errno == ESRCH) return;

		// Binary path is just empty. Get its argv instead
		char args[PATH_MAX];
		(void)getargs(proc->ki_pid, args, sizeof(args));
		needsrestart(proc, "Binary", args);
	} else if (!binonly) {
		unsigned int vmcnt;
		struct kinfo_vmentry *vmaps = procstat_getvmmap(prstat, proc, &vmcnt);

		// Find executable vnode-backed mappings, usually indicating a shared library
		for (unsigned int j = 0; j < vmcnt; j++) {
			struct kinfo_vmentry *kve = &vmaps[j];
			if ((kve->kve_protection & KVME_PROT_EXEC) == KVME_PROT_EXEC &&
			    kve->kve_type == KVME_TYPE_VNODE && !*kve->kve_path) {
				needsrestart(proc, "Library", pathname);
				break;
			}
		}

		procstat_freevmmap(prstat, vmaps);
	}
}

int
main(int argc, char **argv) {
	char ch;
	while ((ch = getopt(argc, argv, "Hb")) != -1)
		switch (ch) {
			case 'H':
				needheader = 0;
				break;
			case 'b':
				binonly = 1;
				break;
			case '?':
			default:
				usage();
		}

	argc -= optind;
	argv += optind;

	struct procstat *prstat = procstat_open_sysctl();
	if (prstat == NULL) errx(1, "procstat_open()");

	unsigned int cnt;

	// List of pids
	if (argc) {
		while (argc--) {
			char *end;
			pid_t pid = strtoimax(*argv, &end, 10);
			if (*end != '\0') usage();
			struct kinfo_proc *p = procstat_getprocs(prstat, KERN_PROC_PID, pid, &cnt);
			if (p == NULL) warn("procstat_getprocs(%d)", pid);
			else {
				if (cnt == 1) checkrestart(prstat, p);
				procstat_freeprocs(prstat, p);
			}
			argv++;
		}
	} else {
		// all processes
		struct kinfo_proc *p = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &cnt);
		if (p == NULL) errx(1, "procstat_getprocs()");

		for (unsigned int i = 0; i < cnt; i++) {
			checkrestart(prstat, &p[i]);
		}

		procstat_freeprocs(prstat, p);
	}

	procstat_close(prstat);
	return 0;
}
