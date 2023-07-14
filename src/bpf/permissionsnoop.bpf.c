/*
 * Copyright (c) 2023 Unibg Seclab (https://seclab.unibg.it)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// include/linux/fs.h
#define MAY_EXEC    0x00000001
#define MAY_WRITE   0x00000002
#define MAY_READ    0x00000004

/* file is open for reading */
#define FMODE_READ      0x1
/* file is open for writing */
#define FMODE_WRITE     0x2
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC      0x20
#define FMODE_CREATED   0x100000

// include/uapi/asm-generic/mman-common.h
#define PROT_READ   0x1     /* page can be read */
#define PROT_WRITE  0x2     /* page can be written */
#define PROT_EXEC   0x4     /* page can be executed */

// include/uapi/linux/limits.h
#define PATH_MAX    4096    /* # chars in a path name including nul */

// linux/include/linux/mm.h
#define VM_SHARED   0x00000008

// include/uapi/linux/mman.h
#define MAP_PRIVATE 0x02    /* changes are private */

#define SRC_MAX     32

char LICENSE[] SEC("license") = "Dual MIT/GPL";
u8 TRUE = true;

// DEBUG
#define DEBUG = 1;

/* STRUCTS */

struct path_event {
    u8 permission;
    unsigned int path_len;
    char src[SRC_MAX];
    char path[PATH_MAX];
};

/* MAPS */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);    // 512 KB
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, PATH_MAX);
  __uint(max_entries, 1);
} tmp_path SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, (BPF_F_NO_PREALLOC));
    __type(key, int);
    __type(value, u8);
} tracee_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size,  sizeof(int));
	__uint(value_size, sizeof(u8));
	__uint(max_entries, 64);
} tid_map SEC(".maps");

/* ATTACHMENT */

/*
 * Trace the current task. It is used on developer's demand to ensure the task
 * operations are going to be traced
 */
SEC("uprobe//proc/self/exe:attach_tracer")
void BPF_KPROBE(attach_tracer) {
	struct task_struct *task = bpf_get_current_task_btf();
	bpf_task_storage_get(&tracee_map, task, &TRUE,
						 BPF_LOCAL_STORAGE_GET_F_CREATE);
#ifdef DEBUG
	bpf_printk("attach_tracer: enabling tracing ON pid %d", task->pid);
#endif /* DEBUG */
}

/*
 * Force tracing inheritance when a process forks itself
 */
SEC("tp_btf/sched_process_fork")
void BPF_PROG(inherit_trace_on_fork, struct task_struct *parent,
			  struct task_struct *child) {
	u8 *is_parent_traced = NULL;
	is_parent_traced = bpf_task_storage_get(&tracee_map, parent, 0, 0);

	if (is_parent_traced) {
		bpf_task_storage_get(&tracee_map, child, &TRUE,
							 BPF_LOCAL_STORAGE_GET_F_CREATE);
#ifdef DEBUG
		bpf_printk("sched_process_fork: inheriting tracing FROM %d TO %d",
				   parent->pid, child->pid);
#endif /* DEBUG */
	}
}

/*
 * Disable tracing of the current task. It is used on process exit to free
 * any tracing configuration associated with the pid of the process.
 */
SEC("tp_btf/sched_process_exit")
void BPF_PROG(delete_trace_on_exit, struct task_struct *child) {
	struct task_struct *task = bpf_get_current_task_btf();
	bool err = bpf_task_storage_delete(&tracee_map, task);
#ifdef DEBUG
	if (!err) {
		bpf_printk("sched_process_exit: exiting FROM %d", task->pid);
	}
#endif /* DEBUG */
}

/* TRACING */

bool is_traced() {
    struct task_struct *task = bpf_get_current_task_btf();
    // check the current task is traced
    u8 *is_traced = (u8 *) bpf_task_storage_get(&tracee_map, task, 0, 0);
    if (is_traced != NULL) {
	    return true;
    }
    int pid = task->pid;
    // check whether the user has attached a policy to a process
    // without using the auto-attach function
    int * res = bpf_map_lookup_elem(&tid_map, &pid);
    if (res != NULL){
#ifdef DEBUG	    
	    bpf_printk("Pid %d listed", pid);
#endif
	    // start tracing the the current task
	    bpf_task_storage_get(&tracee_map, task, &TRUE, BPF_LOCAL_STORAGE_GET_F_CREATE);
	    return true;
    }

    return false;
}

u8 mode_to_permission(fmode_t mode) {
    u8 permission = 0;

    if (mode & FMODE_READ) {
        permission |= MAY_READ;
    }
    if (mode & FMODE_WRITE) {
        permission |= MAY_WRITE;
    }
    if (mode & FMODE_EXEC) {
        permission |= MAY_EXEC;
    }

    return permission;
}

u8 mmap_permission(unsigned long prot, unsigned long flags) {
    u8 permission = 0;

    if (prot & PROT_READ) {
        permission |= MAY_READ;
    }
    if (prot & PROT_WRITE && !(flags & MAP_PRIVATE)) {
        permission |= MAY_WRITE;
    }
    if (prot & PROT_EXEC) {
        permission |= MAY_EXEC;
    }

    return permission;
}

/*
 * Write event to the ring buffer
 *
 * This function relies on bpf_d_path helper function, which is allowed to:
 * - tracing programs with iter attachment type
 * - lsm programs attached to sleepable hook programs (in sleepable_lsm_hooks)
 * - any program attached to functions in btf_allowlist_d_path
 *
 * (see bpf_d_path_allowed implementation at /kernel/trace/bpf_trace.c)
*/
void register_path_event(char *src, struct path *path, u8 permission) {
    struct path_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return;
    }

    bpf_probe_read_kernel_str(event->src, SRC_MAX, src);
    event->path_len = bpf_d_path(path, event->path, PATH_MAX);
    event->permission = permission;
#ifdef DEBUG
    bpf_printk("%s: %s %u", src, event->path, event->permission);
    bpf_printk("%lu", event->path_len);    
#endif /* DEBUG */
	bpf_ringbuf_submit(event, 0);
}

SEC("fentry/security_inode_getattr")
int BPF_PROG(trace_inode_getattr, struct path *path) {
    if (is_traced()) {
        register_path_event("fentry/security_inode_getattr", path, MAY_READ);
    }

    return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(trace_open, struct file *file, int mask) {
    if (file && is_traced()) {
        u8 permission = mode_to_permission(file->f_mode);
        register_path_event("fentry/security_file_open", &file->f_path,
                            permission);
    }

    return 0;
}

/*
 * Trace execve events to capture file executions
 *
 * fentry/security_bprm_check does not belong to btf_allowlist_d_path, but
 * lsm/bprm_check_security belongs to sleepable_lsm_hooks, so we must use
 * the latter to have bpf_d_path available
*/
SEC("lsm/bprm_check_security")
int BPF_PROG(trace_exec, struct linux_binprm *bprm) {
    if (!bprm || !is_traced()) {
        return 0;
    }

    struct file *file;
    u8 permission;

    file = bprm->file;
    if (file) {
        permission = mode_to_permission(file->f_mode) | MAY_EXEC;
        register_path_event("lsm/bprm_check_security", &file->f_path,
                            permission);
    }

    file = bprm->interpreter;   // interpreter specified with the shebang
    if (file) {
        permission = mode_to_permission(file->f_mode) | MAY_EXEC;
        register_path_event("lsm/bprm_check_security", &file->f_path,
                            permission);
    }
    
    file = bprm->executable;    // executable to pass to the interpreter
    if (file) {
        permission = mode_to_permission(file->f_mode) | MAY_EXEC;
        register_path_event("lsm/bprm_check_security", &file->f_path,
                            permission);
    }

    return 0;
}

/*
 * Trace memory mapping events to capture how the memory region hosting the
 * file is protected
 * 
 * fentry/security_mmap_file does not belong to btf_allowlist_d_path, but
 * lsm/mmap_file belongs to sleepable_lsm_hooks, so we must use the latter to
 * have bpf_d_path available
*/
SEC("lsm/mmap_file")
int BPF_PROG(trace_mmap, struct file *file, unsigned long prot,
             unsigned long flags) {
    if (file && is_traced()) {
        u8 permission = mmap_permission(prot, flags);
        register_path_event("lsm/mmap_file", &file->f_path, permission);
    }

    return 0;
}

/*
 * NOTE: The following hooks require patching the kernel by extending
 * btf_allowlist_d_path and sleepable_lsm_hooks
*/

SEC("fentry/security_file_fcntl")
int BPF_PROG(trace_fcntl, struct file *file, unsigned int cmd,
             unsigned long arg) {
    if (file && is_traced()) {
        u8 permission = mode_to_permission(file->f_mode);
        register_path_event("fentry/security_file_fcntl", &file->f_path,
                            permission);
    }

    return 0;
}

SEC("fentry/security_file_ioctl")
int BPF_PROG(trace_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg) {
    if (file && is_traced()) {
        u8 permission = mode_to_permission(file->f_mode);
        register_path_event("fentry/security_file_ioctl", &file->f_path,
                            permission);
    }

    return 0;
}

SEC("fentry/security_file_lock")
int BPF_PROG(trace_lock, struct file *file, unsigned int cmd) {
    if (file && is_traced()) {
        u8 permission = mode_to_permission(file->f_mode);
        register_path_event("fentry/security_file_lock", &file->f_path,
                            permission);
    }

    return 0;
}

SEC("fentry/security_file_mprotect")
int BPF_PROG(trace_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
			 unsigned long prot) {
    if (vma && is_traced()) {
        unsigned long flags = !(vma->vm_flags & VM_SHARED) ? MAP_PRIVATE : 0;
        u8 permission = mmap_permission(prot, flags);
        register_path_event("fentry/security_file_mprotect",
                            &vma->vm_file->f_path, permission);
    }

    return 0;
}

SEC("fentry/security_file_receive")
int BPF_PROG(trace_receive, struct file *file) {
    if (file && is_traced()) {
        u8 permission = mode_to_permission(file->f_mode);
        register_path_event("fentry/security_file_receive", &file->f_path,
                            permission);
    }

    return 0;
}

SEC("fentry/security_file_set_fowner")
int BPF_PROG(trace_set_fowner, struct file *file) {
    if (file && is_traced()) {
        u8 permission = mode_to_permission(file->f_mode);
        register_path_event("fentry/security_file_set_fowner", &file->f_path,
                            permission);
    }

    return 0;
}

// /*
//  * Tarce truncate operations, i.e. using ftruncate.
//  *
//  * The LSM hook was introduced in recent versions of the kernel, so we do not
//  * it available even with our kernel changes yet
//  */
// SEC("fentry/security_file_truncate")
// int BPF_PROG(trace_file_truncate, struct file *file) {
//     if (file && is_traced()) {
//         u8 permission = mode_to_permission(file->f_mode);
//         register_path_event("fentry/security_file_truncate", &file->f_path,
//                             permission);
//     }

//     return 0;
// }

SEC("fentry/security_path_mknod")
int BPF_PROG(trace_mknod, struct path *dir, struct dentry *dentry,
             umode_t mode, unsigned int dev) {
    if (dir && is_traced()) {
        register_path_event("fentry/security_path_mknod", dir,
                            MAY_WRITE | MAY_EXEC);
    }

    return 0;
}

SEC("fentry/security_path_mkdir")
int BPF_PROG(trace_mkdir, struct path *dir, struct dentry *dentry,
             umode_t mode) {
    if (dir && is_traced()) {
        register_path_event("fentry/security_path_mkdir", dir,
                            MAY_WRITE | MAY_EXEC);
    }

    return 0;
}

SEC("fentry/security_path_rmdir")
int BPF_PROG(trace_rmdir, struct path *dir, struct dentry *dentry) {
    if (dir && is_traced()) {
        register_path_event("fentry/security_path_rmdir", dir,
                            MAY_WRITE | MAY_EXEC);
    }

    return 0;
}

SEC("fentry/security_path_unlink")
int BPF_PROG(trace_unlink, struct path *dir, struct dentry *dentry) {
    if (dir && is_traced()) {
        register_path_event("fentry/security_path_unlink", dir,
                            MAY_WRITE | MAY_EXEC);
    }

    return 0;
}

SEC("fentry/security_path_symlink")
int BPF_PROG(trace_symlink, struct path *dir, struct dentry *dentry,
             char *old_name) {
    if (dir && is_traced()) {
        register_path_event("fentry/security_path_symlink", dir,
                            MAY_WRITE | MAY_EXEC);
    }

    return 0;
}

SEC("fentry/security_path_link")
int BPF_PROG(trace_link, struct dentry *old_dentry, struct path *new_dir,
             struct dentry *new_dentry) {
    if (new_dir && is_traced()) {
        register_path_event("fentry/security_path_link", new_dir,
                            MAY_WRITE | MAY_EXEC);
    }

    return 0;
}

SEC("fentry/security_path_rename")
int BPF_PROG(trace_rename, struct path *old_dir, struct dentry *old_dentry,
             struct path *new_dir, struct dentry *new_dentry,
             unsigned int flags) {
    if (new_dir && is_traced()) {
        register_path_event("fentry/security_path_rename", old_dir,
                            MAY_WRITE | MAY_EXEC);
        register_path_event("fentry/security_path_rename", new_dir,
                            MAY_WRITE | MAY_EXEC);
    }

    return 0;
}

SEC("fentry/security_path_truncate")
int BPF_PROG(trace_path_truncate, struct path *path) {
    if (path && is_traced()) {
        register_path_event("fentry/security_path_truncate", path, MAY_WRITE);
    }

    return 0;
}

SEC("fentry/security_path_chmod")
int BPF_PROG(trace_chmod, struct path *path, umode_t mode) {
    if (path && is_traced()) {
        register_path_event("fentry/security_path_chmod", path, MAY_WRITE);
    }

    return 0;
}

// see https://lore.kernel.org/all/20220812052435.523068-1-yhs@fb.com/T/
struct trace_chown_args {
    struct path *path;
    kuid_t uid;
    kgid_t gid;
};
SEC("fentry/security_path_chown")
int trace_chown(struct trace_chown_args *args) {
    if (args && args->path && is_traced()) {
        register_path_event("fentry/security_path_chown", args->path,
                            MAY_WRITE);
    }

    return 0;
}

SEC("fentry/security_path_chroot")
int BPF_PROG(trace_chroot, struct path *path) {
    if (path && is_traced()) {
        register_path_event("fentry/security_path_chroot", path, MAY_EXEC);
    }

    return 0;
}
