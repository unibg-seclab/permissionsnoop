# permissionsnoop

An eBPF-based security observability tool with minimal performance
footprint to identify and record file system-related events generated
by application and processes.

## Prerequisites

- bpftool 7.0.0
- Cargo 1.69.0
- Clang 14.0.0
- Tested with kernel 6.4 (see section below)
- rustc 1.69.0

### NOTE

The utility expects to attach eBPF programs to LSM hooks in order to
capture file system-related security events. As such, the Linux kernel
should have eBPF LSM enabled. Moreover, in order to capture the full
path of the files involved in the events a few small changes to the
kernel are required to make the `bpf_d_path` helper available to all
the hooks we need.

Specifically, we changed:

- `kernel/trace/bpf_trace.c` by expanding the `btf_allowlist_d_path` with:

  ```c
  BTF_ID(func, security_file_fcntl)
  BTF_ID(func, security_file_ioctl)
  BTF_ID(func, security_file_lock)
  BTF_ID(func, security_file_mprotect)
  BTF_ID(func, security_file_set_fowner)
  BTF_ID(func, security_file_receive)
  BTF_ID(func, security_file_truncate)
  BTF_ID(func, security_path_chmod)
  BTF_ID(func, security_path_chown)
  BTF_ID(func, security_path_chroot)
  BTF_ID(func, security_path_link)
  BTF_ID(func, security_path_mkdir)
  BTF_ID(func, security_path_mknod)
  BTF_ID(func, security_path_rename)
  BTF_ID(func, security_path_rmdir)
  BTF_ID(func, security_path_symlink)
  BTF_ID(func, security_path_unlink)
  ```

- `kernel/bpf/bpf_lsm.c` by adding to the `sleepable_lsm_hooks` list the
  following entries:

  ```c
  BTF_ID(func, bpf_lsm_file_fcntl)
  BTF_ID(func, bpf_lsm_file_mprotect)
  BTF_ID(func, bpf_lsm_file_set_fowner)
  BTF_ID(func, bpf_lsm_file_truncate)
  BTF_ID(func, bpf_lsm_path_chmod)
  BTF_ID(func, bpf_lsm_path_chown)
  BTF_ID(func, bpf_lsm_path_chroot)
  BTF_ID(func, bpf_lsm_path_link)
  BTF_ID(func, bpf_lsm_path_mkdir)
  BTF_ID(func, bpf_lsm_path_mknod)
  BTF_ID(func, bpf_lsm_path_rename)
  BTF_ID(func, bpf_lsm_path_rmdir)
  BTF_ID(func, bpf_lsm_path_symlink)
  BTF_ID(func, bpf_lsm_path_truncate)
  BTF_ID(func, bpf_lsm_path_unlink)
  ```

## Quickstart

- Install [prerequisites](#prerequisites)
- Compile the utility from source

  ```sh
	make
  ```

- Example 1, trace the `ls` program

  ```sh
  permissionsnoop -- ls -l
  ```
  
- Example 2, trace a process

  ```sh
  permissionsnoop -- ${PID}
  ```
  

## Usage

Security observability tool to trace filesystem-related events

```usage
eBPF-based security observability tool to trace file system-related events

Usage: permissionsnoop [OPTIONS] <COMPONENT>...

Arguments:
  <COMPONENT>...  A command or a sequence of space-separated thread identifiers.
  Tracing terminates when command exits, and when user inputs <ENTER>
  if thread identifiers are specified.

Options:
  -a, --aggregate  Print aggregate permission on exit
  -h, --help       Print help
```
