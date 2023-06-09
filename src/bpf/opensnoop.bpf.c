#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// include/uapi/linux/limits.h
#define PATH_MAX        4096	/* # chars in a path name including nul */

// include/uapi/asm-generic/fcntl.h
#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_RDWR  	00000001

#define SRC_MAX 32

char LICENSE[] SEC("license") = "Dual MIT/GPL";
const u8 TRUE = true;

/* STRUCTS */

struct path_event {
    char src[SRC_MAX];
    char path[PATH_MAX];
    unsigned int path_len;
    unsigned int flags;
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

bool is_traced() {
    struct task_struct *task = bpf_get_current_task_btf();
    u8 *is_traced = (u8 *) bpf_task_storage_get(&tracee_map, task, 0, 0);
    return is_traced != NULL;
}

void register_path_event(char *src, struct path *path, unsigned int flags) {
    struct path_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return;
    }

    bpf_probe_read_kernel_str(event->src, SRC_MAX, src);
    event->path_len = bpf_d_path(path, event->path, PATH_MAX);
    event->flags = flags;
#ifdef DEBUG
    bpf_printk("%s: %s %s", src, event->path, event->flags);
#endif /* DEBUG */
	bpf_ringbuf_submit(event, 0);
}

/*
 * In the following we are using all the hook points where the bpf_d_path
 * helper function is available according to the btf_allowlist_d_path variable
 * https://github.com/torvalds/linux/blob/master/kernel/trace/bpf_trace.c#L920
*/

// SEC("lsm/file_permission")
// int BPF_PROG(trace_file_permission, struct file *file, int mask) {
//     if (is_traced()) {
//         register_path_event("lsm/file_permission", &file->f_path,
//                             file->f_flags);
//     }

//     return 0;
// }

SEC("lsm/inode_getattr")
int BPF_PROG(trace_inode_getattr, const struct path *path) {
    if (is_traced()) {
        register_path_event("lsm/inode_getattr", path, O_RDONLY);
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(trace_open, struct file *file, int mask) {
    if (is_traced()) {
        register_path_event("lsm/file_open", &file->f_path, file->f_flags);
    }

    return 0;
}

// SEC("lsm/path_truncate")
// int BPF_PROG(trace_truncate, const struct path *path) {
//     if (is_traced()) {
//         register_path_event("lsm/path_truncate", path, O_WRONLY);
//     }

//     return 0;
// }

SEC("fentry/vfs_truncate")
int BPF_PROG(trace_vfs_truncate, const struct path *path, loff_t length) {
    if (is_traced()) {
        register_path_event("fentry/vfs_truncate", path, O_WRONLY);
    }

    return 0;
}

SEC("fentry/vfs_fallocate")
int BPF_PROG(trace_vfs_fallocate, struct file *file, int mode, loff_t offset,
             loff_t len) {
    if (is_traced()) {
        register_path_event("fentry/vfs_fallocate", &file->f_path,
                            file->f_flags);
    }

    return 0;
}

SEC("fentry/dentry_open")
int BPF_PROG(trace_dentry_open, const struct path *path, int flags,
			 const struct cred *cred) {
    if (is_traced()) {
        register_path_event("fentry/dentry_open", path, flags);
    }

    return 0;
}

SEC("fentry/vfs_getattr")
int BPF_PROG(trace_vfs_getattr, const struct path *path, struct kstat *stat,
		     u32 request_mask, unsigned int query_flags) {
    if (is_traced()) {
        register_path_event("fentry/vfs_getattr", path, O_RDONLY);
    }

    return 0;
}

SEC("fentry/filp_close")
int BPF_PROG(trace_filp_close, struct file *filp, fl_owner_t id) {
    if (is_traced()) {
        register_path_event("fentry/filp_close", &filp->f_path, filp->f_flags);
    }

    return 0;
}
