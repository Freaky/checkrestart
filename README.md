# checkrestart

Check for processes that may require restarting.

## Example

```shell
-# checkrestart
44960            weechat        [MISSING LIB]   /usr/local/bin/weechat
81345               tmux        [MISSING EXE]   tmux: server (/tmp/tmux-1001/default)
80307               tmux        [MISSING EXE]   tmux: client (/tmp/tmux-1001/default)
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
