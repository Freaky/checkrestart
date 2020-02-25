
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <libprocstat.h>
#include <libxo/xo.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define CHECKRESTART_XO_VERSION "1"

static bool binonly = false;
static bool needheader = true;
static int termwidth = 0;
static int jid = -1;

static void
usage(void)
{
	xo_error("usage: %s [--libxo] [-bHw] [-j jid] [pid [pid ...]]\n", getprogname());
	exit(EXIT_FAILURE);
}

static bool
parse_int(const char *str, int *value)
{
	char *end;

	*value = strtoimax(str, &end, 10);
	return (*str != '\0' && *end == '\0');
}

static int
gettermwidth(void)
{
	struct winsize ws = { .ws_row = 0 };
	char *colenv;
	int cols;

	colenv = getenv("COLUMNS");
	if (colenv != NULL && parse_int(colenv, &cols) && cols > 0) {
		return (cols);
	}

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, (char *)&ws) != -1 ||
	    ioctl(STDERR_FILENO, TIOCGWINSZ, (char *)&ws) != -1 ||
	    ioctl(STDIN_FILENO, TIOCGWINSZ, (char *)&ws) != -1) {
		return (ws.ws_col);
	}

	return (0);
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
needsrestart(const struct kinfo_proc *proc, const char *updated, const char *command)
{
	char fmtbuf[40];
	int col, width;

	col = 0;

	if (needheader) {
		needheader = false;
		xo_emit(
		    "{T:/%5s} {T:/%5s} {T:/%-12.12s} {T:/%-7s} {T:/%s}\n",
		    "PID", "JID", "NAME", "UPDATED", "COMMAND"
		);
	}

	xo_open_instance("process");
	xo_emit("{k:pid/%5d/%d} ",      proc->ki_pid);  col += 6;
	xo_emit("{k:jid/%5d/%d} ",      proc->ki_jid);  col += 6;
	xo_emit("{:name/%-12.12s/%s} ", proc->ki_comm); col += 13;
	xo_emit("{:updated/%-7s/%s} ",  updated);       col += 8;

	if (termwidth && xo_get_style(NULL) == XO_STYLE_TEXT) {
		width = MAX(termwidth - col, 7);
		snprintf(fmtbuf, sizeof(fmtbuf), "{:command/%%-%d.%ds}\n", width, width);
		xo_emit(fmtbuf, command);
	} else {
		xo_emit("{:command/%s}\n", command);
	}
	xo_close_instance("process");
}

static void
checkrestart(struct procstat *prstat, struct kinfo_proc *proc)
{
	char args[PATH_MAX], pathname[PATH_MAX];
	struct kinfo_vmentry *kve, *vmaps;
	unsigned int cnt, error, i;

	// Skip kernel processes
	if (proc->ki_ppid == 0) {
		return;
	}

	// If -j is specified and value is a valid JID, skip non-matching JID
	if (jid >= 0 && proc->ki_jid != jid) {
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

		for (i = 0; i < cnt; i++) {
			kve = &vmaps[i];

			if (kve->kve_protection & KVME_PROT_EXEC && // executable mapping
			    kve->kve_type == KVME_TYPE_VNODE &&     // backed by a vnode
			    kve->kve_path[0] == '\0') {             // with no associated path
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
	unsigned int cnt, i;
	int ch, rc;
	pid_t pid;

	rc = EXIT_SUCCESS;
	termwidth = gettermwidth();
	argc = xo_parse_args(argc, argv);
	if (argc < 0) {
		return (EXIT_FAILURE);
	}

	while ((ch = getopt(argc, argv, "bHwj:")) != -1) {
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
		case 'j':
			jid = atoi(optarg);
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	prstat = procstat_open_sysctl();
	if (prstat == NULL) {
		xo_errx(EXIT_FAILURE, "procstat_open()");
	}

	xo_set_version(CHECKRESTART_XO_VERSION);
	xo_open_container("checkrestart");
	xo_open_list("process");

	if (argc) {
		while (argc--) {
			if (!parse_int(*argv, &pid) || pid <= 0) {
				usage();
			}

			p = procstat_getprocs(prstat, KERN_PROC_PID, pid, &cnt);
			if (p == NULL) {
				xo_warn("procstat_getprocs(%d)", pid);
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
			xo_warn("procstat_getprocs()");
			rc = EXIT_FAILURE;
		} else {
			for (i = 0; i < cnt; i++) {
				checkrestart(prstat, &p[i]);
			}
			procstat_freeprocs(prstat, p);
		}
	}

	xo_close_list("process");
	xo_close_container("checkrestart");
	xo_finish();

	procstat_close(prstat);
	return (rc);
}
