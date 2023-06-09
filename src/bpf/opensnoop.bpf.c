#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// include/uapi/linux/limits.h
#define PATH_MAX    4096    /* # chars in a path name including nul */

// include/uapi/asm-generic/fcntl.h
#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_RDWR      00000002

// #define O_CREAT		00000100	// create when does not exist
// #define O_EXCL		00000200	// create when does not exist, fails otherwise
// #define O_DIRECTORY	00200000
// #define __O_TMPFILE	020000000
// #define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)   // create unnamed temporary file

// NOTES (https://man7.org/linux/man-pages/man2/open.2.html):
// - Opening a file or directory with the O_PATH flag requires no permissions
//   on the object itself (but does require execute permission on the
//   directories in the path prefix).
// - An O_EXCL without O_CREAT has undefined behavior, unless working on a
//   block device
// - An O_TMPFILE without O_EXCL can be made permanent with linkat
// - An O_TRUNC without writing access mode has unspecified effect

// include/uapi/asm-generic/mman-common.h
#define PROT_READ   0x1     /* page can be read */
#define PROT_WRITE  0x2     /* page can be written */
#define PROT_EXEC   0x4     /* page can be executed */

// include/uapi/linux/mman.h
#define MAP_PRIVATE 0x02    /* changes are private */

// include/linux/fs.h
#define MAY_EXEC    0x00000001
#define MAY_WRITE   0x00000002
#define MAY_READ    0x00000004

#define SRC_MAX     32

char LICENSE[] SEC("license") = "Dual MIT/GPL";
const u8 TRUE = true;

/* STRUCTS */

struct path_event {
    char src[SRC_MAX];
    char path[PATH_MAX];
    unsigned int path_len;
    u8 permission;
};

/* MAPS */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);    // 256 KB
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

// TODO: Use f_mode when feasible
// TODO: Remove unnecessary hook points

bool is_traced() {
    struct task_struct *task = bpf_get_current_task_btf();
    u8 *is_traced = (u8 *) bpf_task_storage_get(&tracee_map, task, 0, 0);
    return is_traced != NULL;
}

u8 flags_to_permission(unsigned int flags) {
    u8 permission = 0;

    if (flags & O_WRONLY) {
        permission = MAY_WRITE;
    } else if (flags & O_RDWR) {
        permission = MAY_READ | MAY_WRITE;
    } else {
        permission = MAY_READ;
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
#endif /* DEBUG */
	bpf_ringbuf_submit(event, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(trace_exec, struct linux_binprm *bprm) {
    if (!is_traced()) {
        return 0;
    }

    struct file *file;
    u8 permission;

    file = bprm->file;
    if (file) {
        permission = flags_to_permission(file->f_flags) | MAY_EXEC;
        register_path_event("lsm/bprm_check_security", &file->f_path,
                            permission);
    }

    file = bprm->interpreter;   // interpreter specified with the shebang
    if (file) {
        permission = flags_to_permission(file->f_flags) | MAY_EXEC;
        register_path_event("lsm/bprm_check_security", &file->f_path,
                            permission);
    }
    
    file = bprm->executable;    // executable to pass to the interpreter
    if (file) {
        permission = flags_to_permission(file->f_flags) | MAY_EXEC;
        register_path_event("lsm/bprm_check_security", &file->f_path,
                            permission);
    }

    return 0;
}

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
 * In the following we are using all the hook points where the bpf_d_path
 * helper function is available according to the btf_allowlist_d_path variable
 * https://github.com/torvalds/linux/blob/master/kernel/trace/bpf_trace.c#L920
*/

// SEC("lsm/file_permission")
// int BPF_PROG(trace_file_permission, struct file *file, int mask) {
//     if (is_traced()) {
//         u8 permission = flags_to_permission(file->f_flags);
//         register_path_event("lsm/file_permission", &file->f_path,
//                             permission);
//     }

//     return 0;
// }

SEC("lsm/inode_getattr")
int BPF_PROG(trace_inode_getattr, const struct path *path) {
    if (is_traced()) {
        register_path_event("lsm/inode_getattr", path, MAY_READ);
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(trace_open, struct file *file, int mask) {
    if (is_traced()) {
        u8 permission = flags_to_permission(file->f_flags);
        register_path_event("lsm/file_open", &file->f_path, permission);
    }

    return 0;
}

// SEC("lsm/path_truncate")
// int BPF_PROG(trace_truncate, const struct path *path) {
//     if (is_traced()) {
//         register_path_event("lsm/path_truncate", path, MAY_WRITE);
//     }

//     return 0;
// }

SEC("fentry/vfs_truncate")
int BPF_PROG(trace_vfs_truncate, const struct path *path, loff_t length) {
    if (is_traced()) {
        register_path_event("fentry/vfs_truncate", path, MAY_WRITE);
    }

    return 0;
}

SEC("fentry/vfs_fallocate")
int BPF_PROG(trace_vfs_fallocate, struct file *file, int mode, loff_t offset,
             loff_t len) {
    if (is_traced()) {
        u8 permission = flags_to_permission(file->f_flags);
        register_path_event("fentry/vfs_fallocate", &file->f_path, permission);
    }

    return 0;
}

SEC("fentry/dentry_open")
int BPF_PROG(trace_dentry_open, const struct path *path, int flags,
			 const struct cred *cred) {
    if (is_traced()) {
        u8 permission = flags_to_permission(flags);
        register_path_event("fentry/dentry_open", path, permission);
    }

    return 0;
}

SEC("fentry/vfs_getattr")
int BPF_PROG(trace_vfs_getattr, const struct path *path, struct kstat *stat,
		     u32 request_mask, unsigned int query_flags) {
    if (is_traced()) {
        register_path_event("fentry/vfs_getattr", path, MAY_READ);
    }

    return 0;
}

SEC("fentry/filp_close")
int BPF_PROG(trace_filp_close, struct file *filp, fl_owner_t id) {
    if (is_traced()) {
        u8 permission = flags_to_permission(filp->f_flags);
        register_path_event("fentry/filp_close", &filp->f_path, permission);
    }

    return 0;
}
