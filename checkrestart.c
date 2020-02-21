
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/user.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <libprocstat.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

static bool binonly = false;
static bool needheader = true;
static int termwidth = 0;

static void
usage(void)
{
	printf("usage: checkrestart [-bHw] [pid [pid ...]]\n");
	exit(EXIT_FAILURE);
}

static int
gettermwidth(void)
{
	struct winsize ws = { .ws_row = 0 };
	char *colenv, *end;
	int cols;

	colenv = getenv("COLUMNS");
	if (colenv != NULL && *colenv != '\0') {
		cols = strtoimax(colenv, &end, 10);
		if (*end != '\0') {
			return cols;
		}
	}

	if ((ioctl(STDOUT_FILENO, TIOCGWINSZ, (char *)&ws) == -1 &&
	    ioctl(STDERR_FILENO, TIOCGWINSZ, (char *)&ws) == -1 &&
	    ioctl(STDIN_FILENO, TIOCGWINSZ, (char *)&ws) == -1)) {
		return 0;
	} else {
		return ws.ws_col;
	}
}

static int
getprocstr(pid_t pid, int node, char *str, size_t maxlen)
{
	int name[4] = { CTL_KERN, KERN_PROC, node, pid };
	size_t len = maxlen;
	int error;

	str[0] = '\0';
	error = sysctl(name, nitems(name), str, &len, NULL, 0);
	if (error != 0) {
		if (errno == ENOMEM) {
			str[len] = '\0';
		} else {
			return (errno);
		}
	}
	return (0);
}

static int
getpathname(pid_t pid, char *pathname, size_t maxlen)
{
	return (getprocstr(pid, KERN_PROC_PATHNAME, pathname, maxlen));
}

static int
getargs(pid_t pid, char *args, size_t maxlen)
{
	return (getprocstr(pid, KERN_PROC_ARGS, args, maxlen));
}

static void
needsrestart(const struct kinfo_proc *proc, const char *why, const char *note)
{
	int printed;

	if (needheader) {
		needheader = false;
		printf("%5s %5s %-12.12s %-7s %s\n", "PID", "JID", "PROCESS", "UPDATED", "COMMAND");
	}

	printed = printf("%5d %5d %-12.12s %-7s ", proc->ki_pid, proc->ki_jid, proc->ki_comm, why);
	if (printed < 0) {
		errx(EXIT_FAILURE, "stdout");
	}

	if (termwidth) {
		printf("%.*s\n", MAX(termwidth - printed, 8), note);
	} else {
		puts(note);
	}
}

static void
checkrestart(struct procstat *prstat, struct kinfo_proc *proc)
{
	char pathname[PATH_MAX], args[PATH_MAX];
	struct kinfo_vmentry *vmaps, *kve;
	unsigned int error, i, cnt;

	// Skip kernel processes
	if (proc->ki_ppid == 0) {
		return;
	}

	error = getpathname(proc->ki_pid, pathname, sizeof(pathname));
	if (error != 0 && error != ENOENT) {
		return;
	}

	if (error == ENOENT) {
		// Verify ENOENT isn't down to the process going away
		if (kill(proc->ki_pid, 0) == -1 && errno == ESRCH) {
			return;
		}

		// Binary path is just empty. Get its argv instead
		(void)getargs(proc->ki_pid, args, sizeof(args));
		needsrestart(proc, "Binary", args);
	} else if (!binonly) {
		vmaps = procstat_getvmmap(prstat, proc, &cnt);
		if (vmaps == NULL) {
			return;
		}

		// Find executable vnode-backed mappings, usually indicating a shared library
		for (i = 0; i < cnt; i++) {
			kve = &vmaps[i];

			if ((kve->kve_protection & KVME_PROT_EXEC) == KVME_PROT_EXEC &&
			    kve->kve_type == KVME_TYPE_VNODE && *kve->kve_path == '\0') {
				needsrestart(proc, "Library", pathname);
				break;
			}
		}

		procstat_freevmmap(prstat, vmaps);
	}
}

int
main(int argc, char *argv[])
{
	struct kinfo_proc *p;
	struct procstat *prstat;
	char *end;
	unsigned int cnt, i;
	int rc = EXIT_SUCCESS;
	pid_t pid;
	char ch;

	termwidth = gettermwidth();

	while ((ch = getopt(argc, argv, "bHw")) != -1)
		switch (ch) {
		case 'b':
			binonly = true;
			break;
		case 'H':
			needheader = false;
			break;
		case 'w':
			termwidth = 0;
			break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	prstat = procstat_open_sysctl();
	if (prstat == NULL) {
		errx(EXIT_FAILURE, "procstat_open()");
	}

	if (argc) {
		while (argc--) {
			pid = strtoimax(*argv, &end, 10);
			if (*end != '\0' || pid <= 0) {
				usage();
			}

			p = procstat_getprocs(prstat, KERN_PROC_PID, pid, &cnt);
			if (p == NULL) {
				warn("procstat_getprocs(%d)", pid);
				rc = EXIT_FAILURE;
			} else {
				if (cnt == 1) {
					checkrestart(prstat, p);
				}
				procstat_freeprocs(prstat, p);
			}
			argv++;
		}
	} else {
		p = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &cnt);
		if (p == NULL) {
			warn("procstat_getprocs()");
			rc = EXIT_FAILURE;
		} else {
			for (i = 0; i < cnt; i++) {
				checkrestart(prstat, &p[i]);
			}
			procstat_freeprocs(prstat, p);
		}
	}

	procstat_close(prstat);
	return (rc);
}
