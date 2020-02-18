# NAME

**checkrestart** - check for processes that may need restarting

# SYNOPSIS

**checkrestart**

# DESCRIPTION

The **checkrestart** command searches for processes without associated executable or library paths, implying a software upgrade has replaced them since it was started.

This may produce false-positives, since paths can also be discarded by the kernel due to VFS cache evictions, but this is likely to be rare.

**checkrestart** does not perform any system changes itself - it is strictly informational.  It is the responsibility of the system administrator to interpret the results and take any necessary action.

While **checkrestart** does work partially as a normal user, it should be executed as the superuser for full functionality.

# EXAMPLES

	 # checkrestart
	  PID   JID         COMMAND UPDATED ARGS
	44960     0         weechat Library /usr/local/bin/weechat
	81345     0            tmux  Binary tmux: server (/tmp/tmux-1001/default)
	80307     0            tmux  Binary tmux: client (/tmp/tmux-1001/default)
	18115     1       memcached  Binary /usr/local/bin/memcached

This output indicates **weechat** is using an out of date library, a **tmux** client/server pair is using an out-of-date executable, having replaced its arguments list obscuring its location, and **memcached** , running in Jail 1, is also out of date having left its arguments list as the full path to its original executable.

# SEE ALSO

procstat(1)

# HISTORY

A **checkrestart** command first appeared in the debian-extras package in Debian Linux.

This **checkrestart** implementation performs a similar, but not identical task, and takes the name because why not.

# AUTHORS

Thomas Hurst &lt;tom@hur.st&gt;

