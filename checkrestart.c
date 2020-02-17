
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <err.h>
#include <errno.h>
#include <libprocstat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
getpathname(pid_t pid, char *pathname, size_t maxlen) {
	size_t len = maxlen;
	int name[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid };
	pathname[0] = '\0';
	int error = sysctl(name, nitems(name), pathname, &len, NULL, 0);
	if (error != 0) return errno;
	else return 0;
}

static int
getargs(pid_t pid, char *args, size_t maxlen) {
	size_t len = maxlen;
	int name[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, pid };
	args[0] = '\0';
	int error = sysctl(name, nitems(name), args, &len, NULL, 0);
	if (error != 0) return errno;
	else return 0;
}


int main(void) {
	struct procstat *prstat = procstat_open_sysctl();
	if (prstat == NULL) errx(1, "procstat_open()");

	// List all procs
	unsigned int cnt;
	struct kinfo_proc *p = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &cnt);
	if (p == NULL) errx(1, "procstat_getprocs()");

	// For each proc
	for (unsigned int i = 0; i < cnt; i++) {
		char pathname[PATH_MAX];
		struct kinfo_proc *proc = &p[i];

		// Skip kernel procs
		if (proc->ki_ppid == 0) continue;

		// Get its executable path, no such file or directory means it's missing
		// ... could also mean the process doesn't exist :/
		int error = getpathname(proc->ki_pid, pathname, sizeof(pathname));
		if (error != 0 && error != ENOENT) continue;
		if (error == ENOENT) {
			// Try to find the path from the argument list
			char args[PATH_MAX];
			(void)getargs(proc->ki_pid, args, sizeof(args)); // strictly best effort
			// missing executable, immediate restart candidate
			// search plists for files with the name of this executable as potential candidates
			printf("%05d\t%16s\t[MISSING EXECUTABLE]\t%s\n", proc->ki_pid, proc->ki_comm, args);
		} else {
			// get vm map, find executable vn mappings with no associated file
			// or with file not in plist
		}
	}

	procstat_freeprocs(prstat, p);
	procstat_close(prstat);
}
