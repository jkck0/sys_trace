# `sys_trace`
A toy version of [`strace`](https://strace.io/), written in C.

## Usage
`sys_trace` can be used as follows:
```
$ ./sys_trace tracee tracee_arg tracee_arg2 ...
```

`sys_trace` does not currently support any flags, so there's nothing more to it.

## Installation
### Prerequisites
Building `sys_trace` requires:
- an install of Python 3, which is used to download and extract the syscall numbers from the Linux kernel source code. Because of this, an internet connection is required for the build process
- the `just` command runner, which is used for building. `just` can be installed [here]((https://github.com/casey/just))

### Building
First, clone the source code:
```
$ git clone https://github.com/jkck0/sys_trace.git
```

 After installing the prerequisites, it's as simple as:
```
$ just build
```

This will create a standalone `sys_trace` binary in the directory of the `justfile`.
