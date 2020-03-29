# NAME

**checkrestart** - check for processes that may need restarting

# SYNOPSIS

**checkrestart** \[**--libxo**] \[**-bHw**] \[**-j**&nbsp;*jail*] \[**-u**&nbsp;*user*] \[*proc&nbsp;...*]

# DESCRIPTION

The **checkrestart** command attempts to find processes that need restarting following a software upgrade, as indicated by their underlying executable or shared libraries no longer appearing on disk.

**checkrestart** does not perform any system changes itself &#8212; it is strictly informational and best-effort (See the *BUGS* section). It is the responsibility of the system administrator to interpret the results and take any necessary action.

For full system-wide checks, **checkrestart** should be executed as the superuser to allow it access to global virtual memory mappings.

The following options are available:

**--libxo**

> Generate formatted output via libxo(3) in a selection of human and machine-readable formats.
> See xo\_parse\_args(3) for details on available arguments.

**-b**

> Check only for missing binaries, skipping the far more expensive check for stale libraries.

**-H**

> Suppress the header.

**-w**

> Print the full width of the ARGUMENTS column even if it will wrap in the terminal.

**-j** *jail*

> Filter output by specified jail name or ID.

**-u** *user*

> Filter output by specified user name or ID.

If any *proc* operands are specified, they are treated as process names, IDs, and group IDs to limit checks to.

# EXAMPLES

Check all processes visible by the user:

	 # checkrestart
	  PID   JID USER         COMMAND      WHY ARGUMENTS
	44960     0 freaky       weechat      lib /usr/local/bin/weechat
	81345     0 freaky       tmux         bin tmux: server (/tmp/tmux-1001/default)
	80307     0 freaky       tmux         bin tmux: client (/tmp/tmux-1001/default)
	18115     1 nobody       memcached    bin /usr/local/bin/memcached

This output indicates **weechat** is using an out of date library, a **tmux** client/server pair is using an out-of-date executable, having replaced its arguments list obscuring its location, and **memcached**, running in jail 1, is also out of date having left its arguments list as the full path to its original executable.

Check only processes named weechat and tmux:

	 # checkrestart weechat tmux

Check only processes with PID 142 and 157:

	 # checkrestart 142 157

Check only processes in PGID 117:

	 # checkrestart -- -117

# SEE ALSO

procstat(1), libxo(3), xo\_parse\_args(3), jail(8), service(8)

# HISTORY

A **checkrestart** command first appeared in the debian-extras package in Debian Linux.

This implementation follows a similar idea, and is based on a prior version in the author's **pkg-cruft** Ruby script.

An unrelated but similar **checkrestart** command is also available as an OpenBSD port.

# AUTHORS

Thomas Hurst &lt;tom@hur.st&gt;

# BUGS

**checkrestart** may report both false positives and false negatives, depending on program and kernel behaviour, and should be considered strictly "best-effort".

In particular, retrieval of pathnames is implemented using the kernel's name cache &#8212; if an executable or library path is not in the name cache due to an eviction, or use of a file system which does not use the name cache, **checkrestart** will consider this the same as if a file is missing.

The use of the name cache also means it is not yet possible to report which files are considered missing.
