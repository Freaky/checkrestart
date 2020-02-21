# NAME

**checkrestart** - check for processes that may need restarting

# SYNOPSIS

**checkrestart** \[**-Hb**] \[*pid&nbsp;...*]

# DESCRIPTION

The **checkrestart** command attempts to find processes that need restarting following a software upgrade, as indicated by their underlying executable or shared libraries no longer appearing on disk.

**checkrestart** does not perform any system changes itself &#8212; it is strictly informational and best-effort (See the *BUGS* section). It is the responsibility of the system administrator to interpret the results and take any necessary action.

For full system-wide checks, **checkrestart** should be executed as the superuser to allow it access to global virtual memory mappings.

The following options are available:

**-H**

> Suppress the header.

**-b**

> Check only for missing binaries, skipping the far more expensive check for stale
> libraries.

# EXAMPLES

	 # checkrestart
	  PID   JID         PROCESS UPDATED COMMAND
	44960     0         weechat Library /usr/local/bin/weechat
	81345     0            tmux  Binary tmux: server (/tmp/tmux-1001/default)
	80307     0            tmux  Binary tmux: client (/tmp/tmux-1001/default)
	18115     1       memcached  Binary /usr/local/bin/memcached

This output indicates **weechat** is using an out of date library, a **tmux** client/server pair is using an out-of-date executable, having replaced its arguments list obscuring its location, and **memcached**, running in Jail 1, is also out of date having left its arguments list as the full path to its original executable.

# SEE ALSO

procstat(1), service(8)

# HISTORY

A **checkrestart** command first appeared in the debian-extras package in Debian Linux.

This **checkrestart** implementation performs a similar, but not identical task, and takes the name because why not. It is based on a similar implementation in the author's previous **pkg-cruft** Ruby script.

# AUTHORS

Thomas Hurst &lt;tom@hur.st&gt;

# BUGS

**checkrestart** may report both false positives and false negatives, depending on program and kernel behaviour, and should be considered strictly "best-effort".

It is not currently possible to report what files are missing due to limitations of the underlying interfaces.
