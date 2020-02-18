# checkrestart

Check for processes that may require restarting.

## Example

```shell
-# checkrestart
  PID               COMM         MISSING        ARGS
03945              httpd         Library        /usr/local/sbin/httpd
03572              httpd         Library        /usr/local/sbin/httpd
03299              httpd         Library        /usr/local/sbin/httpd
31388              httpd         Library        /usr/local/sbin/httpd
91629              httpd         Library        /usr/local/sbin/httpd
68718              httpd         Library        /usr/local/sbin/httpd
32008              httpd         Library        /usr/local/sbin/httpd
31647              httpd         Library        /usr/local/sbin/httpd
50138              httpd         Library        /usr/local/sbin/httpd
59709              httpd         Library        /usr/local/sbin/httpd
02641              httpd         Library        /usr/local/sbin/httpd
70820              httpd         Library        /usr/local/sbin/httpd
33494              named          Binary        /usr/local/sbin/named
44960            weechat         Library        /usr/local/bin/weechat
81345               tmux          Binary        tmux: server (/tmp/tmux-1001/default)
80307               tmux          Binary        tmux: client (/tmp/tmux-1001/default)
59517        mosh-server          Binary        mosh-server
77424          freshclam          Binary        /usr/local/bin/freshclam
73780              clamd          Binary        /usr/local/sbin/clamd
21134          memcached         Library        /usr/local/bin/memcached
22601            vnstatd          Binary        /usr/local/sbin/vnstatd
```

## How it works

`checkrestart` searches for processes without an associated executable path, indicating
it's been removed or replaced.

Failing that, it searches process virtual memory maps for executable file-backed mappings
without an associated path - indicating a library that's also been removed or replaced.

Neither of these are expected to be bullet proof - a missing path could just indicate
the entry has been evicted from the namecache, but the approach has proven useful since
its original implementation in [`pkg-cruft`](https://github.com/Freaky/pkg-cruft).

`root` is required for full operation.

## Compatibility

Written for and tested on FreeBSD.
