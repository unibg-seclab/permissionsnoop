#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// include/linux/compiler_types.h
#define __force     __attribute__((force))

// include/linux/fs.h
#define MAY_EXEC    0x00000001
#define MAY_WRITE   0x00000002
#define MAY_READ    0x00000004

/* file is open for reading */
#define FMODE_READ      ((__force fmode_t)0x1)
/* file is open for writing */
#define FMODE_WRITE     ((__force fmode_t)0x2)
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC      ((__force fmode_t)0x20)
#define FMODE_CREATED   ((__force fmode_t)0x100000)

// include/uapi/asm-generic/mman-common.h
#define PROT_READ   0x1     /* page can be read */
#define PROT_WRITE  0x2     /* page can be written */
#define PROT_EXEC   0x4     /* page can be executed */

// include/uapi/linux/limits.h
#define PATH_MAX    4096    /* # chars in a path name including nul */

// include/uapi/linux/mman.h
#define MAP_PRIVATE 0x02    /* changes are private */

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

// TODO: Keep track of creation and removal events using other hooks
// TODO: Trace mprotect to capture changes in memory mapping protection

bool is_traced() {
    struct task_struct *task = bpf_get_current_task_btf();
    u8 *is_traced = (u8 *) bpf_task_storage_get(&tracee_map, task, 0, 0);
    return is_traced != NULL;
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
#endif /* DEBUG */
	bpf_ringbuf_submit(event, 0);
}

SEC("fentry/security_inode_getattr")
int BPF_PROG(trace_inode_getattr, const struct path *path) {
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
