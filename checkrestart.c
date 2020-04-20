
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <jail.h>
#include <libprocstat.h>
#include <libxo/xo.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define CHECKRESTART_XO_VERSION   "2"
#define CHECKRESTART_XO_CONTAINER "checkrestart"
#define CHECKRESTART_XO_PROCESS   "process"

enum Reason { MissingExe, MissingLib };

static int filter_jid = -1;
static int termwidth = 0;
static uid_t filter_uid = 0;
static bool binonly = false;
static bool jflag = false;
static bool needheader = true;
static bool uflag = false;

static void
usage(void)
{
	xo_error("usage: %s [--libxo] [-bHw] [-j jail] [-u [user]] [proc ...]\n", getprogname());
	xo_finish();
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

static char *
user_getname(uid_t uid) {
	static char uidstr[11] = "";
	struct passwd *pw = getpwuid(uid);

	if (pw != NULL) {
		return (pw->pw_name);
	} else {
		snprintf(uidstr, sizeof(uidstr), "%d", (unsigned int)uid);
		return (uidstr);
	}
}

static bool
user_getuid(const char *username, uid_t *uid) {
	struct passwd *pw = getpwnam(username);

	if (pw != NULL) {
		*uid = pw->pw_uid;
		return (true);
	} else {
		return (false);
	}
}

static void
needsrestart(const struct kinfo_proc *proc, const enum Reason reason, const char *args)
{
	char fmtbuf[sizeof("{:arguments/%.4294967295s}\n")];
	int col, width;

	if (needheader) {
		needheader = false;
		xo_emit(
		    "{Tw:/%5s}{Tw:/%5s}{Tw:/%-12.12s}{Tw:/%-12.12s}{Tw:/%-3s}{T:/%s}\n",
		    "PID", "JID", "USER", "COMMAND", "WHY", "ARGUMENTS"
		);
	}

	xo_open_instance(CHECKRESTART_XO_PROCESS);
	col  = xo_emit("{kw:pid/%5d/%d}",         proc->ki_pid);
	col += xo_emit("{w:jid/%5d/%d}",          proc->ki_jid);
	col += xo_emit("{e:uid/%d/%d}",           proc->ki_uid);
	col += xo_emit("{w:user/%-12.12s/%s}",    user_getname(proc->ki_uid));
	col += xo_emit("{w:command/%-12.12s/%s}", proc->ki_comm);
	col += xo_emit("{w:why/%-3s/%s}",         reason == MissingExe ? "bin" : ".so");

	if (termwidth && xo_get_style(NULL) == XO_STYLE_TEXT) {
		width = MAX(termwidth - col, (int)sizeof("ARGUMENTS") - 1);
		snprintf(fmtbuf, sizeof(fmtbuf), "{:arguments/%%.%ds}\n", width);
		xo_emit(fmtbuf, args);
	} else {
		xo_emit("{:arguments/%s}\n", args);
	}
	xo_close_instance(CHECKRESTART_XO_PROCESS);
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

	if (jflag && proc->ki_jid != filter_jid) {
		return;
	}

	if (uflag && proc->ki_uid != filter_uid) {
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
		needsrestart(proc, MissingExe, args);
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
				needsrestart(proc, MissingLib, pathname);
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
	int ch, rc, filterc;
	pid_t pid;

	rc = EXIT_FAILURE;
	termwidth = gettermwidth();

	xo_set_flags(NULL, XOF_WARN | XOF_COLUMNS);
	argc = xo_parse_args(argc, argv);
	if (argc < 0) {
		return (EXIT_FAILURE);
	}

	while ((ch = getopt(argc, argv, "bHj:u:w")) != -1) {
		switch (ch) {
		case 'b':
			binonly = true;
			break;
		case 'H':
			needheader = false;
			break;
		case 'j':
			jflag = true;
			if (parse_int(optarg, &filter_jid)) {
				if (filter_jid < 0) {
					usage();
				}
			} else {
				filter_jid = jail_getid(optarg);
				if (filter_jid == -1) {
					xo_errx(EXIT_FAILURE, "jail \"%s\" not found", optarg);
				}
			}
			break;
		case 'u':
			uflag = true;
			if (!parse_int(optarg, (int *)&filter_uid) && !user_getuid(optarg, &filter_uid)) {
				xo_errx(EXIT_FAILURE, "user \"%s\" not found", optarg);
			}
			break;
		case 'w':
			termwidth = 0;
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

	p = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &cnt);
	if (p == NULL) {
		xo_warn("procstat_getprocs()");
	} else {
		xo_set_version(CHECKRESTART_XO_VERSION);
		xo_open_container(CHECKRESTART_XO_CONTAINER);
		xo_open_list(CHECKRESTART_XO_PROCESS);

		for (i = 0; i < cnt; i++) {
			if (argc) {
				for (filterc = 0; filterc < argc; filterc++) {
					if (!parse_int(argv[filterc], &pid)) {
						pid = 0;
					} else if (pid == 0) {
						usage();
					}

					if (
					    (pid > 0 && p[i].ki_pid == pid) ||
					    (pid < 0 && p[i].ki_pgid == abs(pid)) ||
					    (pid == 0 && strcmp(argv[filterc], p[i].ki_comm) == 0)
					) {
						rc = EXIT_SUCCESS;
						checkrestart(prstat, &p[i]);
						break;
					}
				}
			} else {
				rc = EXIT_SUCCESS;
				checkrestart(prstat, &p[i]);
			}
		}

		xo_close_list(CHECKRESTART_XO_PROCESS);
		xo_close_container(CHECKRESTART_XO_CONTAINER);

		procstat_freeprocs(prstat, p);
	}
	xo_finish();

	procstat_close(prstat);
	return (rc);
}
