#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const u32 PATH_SIZE = 4096;
const u8 TRUE = true;

/* MAPS */

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, PATH_SIZE + 255);
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

// TODO: Use syscall kernel hooks to avoid LSM dependency (and issues with bpf_d_path)
// TODO: Use ring buffer to send path events to user space
// TODO: Attach the same function to multiple kernel hooks
// TODO: Fix check of the path size

bool is_traced() {
    struct task_struct *task = bpf_get_current_task_btf();
    u8 *is_traced = (u8 *) bpf_task_storage_get(&tracee_map, task, 0, 0);
    return is_traced != NULL;
}

/*
 * Initialize the char buffer given with the full path
 */
static int set_full_path(struct path *path, struct dentry *dentry,
                         char *full_path) {
  int pos = bpf_d_path(path, full_path, PATH_SIZE) - 1;
  // Ensure full path not empty and not exceeding PATH_SIZE characters
  if (pos < 0 || pos >= PATH_SIZE)
    return 1;

  if (dentry) {
    full_path[pos] = '/';

    // // Ensure the path component does not exceed 255 characters and the full
    // // path does not exceed PATH_SIZE characters
    // unsigned int max_size = 255;
    // int remaining_size = PATH_SIZE - (pos + 1);
    // if (remaining_size >= 0 && max_size > remaining_size)
    //   max_size = remaining_size;

    // bpf_probe_read_str(full_path + pos + 1, max_size, dentry->d_name.name);
    bpf_probe_read_str(full_path + pos + 1, 255, dentry->d_name.name);
  }

  return 0;
}

void print_path(struct path *path, struct dentry *dentry) {
    int idx = 0;
    char *full_path = bpf_map_lookup_elem(&tmp_path, &idx);
    if (!full_path) {
        return;
    }

    // Retrieve the path of the access request
    int err = set_full_path(path, dentry, full_path);
    if (!err) {
        bpf_printk("%s\n", full_path);
    }
}

SEC("lsm/path_unlink")
int BPF_PROG(trace_unlink, const struct path *dir, struct dentry *dentry) {
    if (is_traced()) {
        print_path(dir, dentry);
    }

    return 0;
}

SEC("lsm/path_rmdir")
int BPF_PROG(trace_rmdir, const struct path *dir, struct dentry *dentry) {
    if (is_traced()) {
        print_path(dir, dentry);
    }

    return 0;
}

SEC("lsm/path_mkdir")
int BPF_PROG(trace_mkdir, const struct path *dir, struct dentry *dentry,
	         umode_t mode) {
    if (is_traced()) {
        print_path(dir, dentry);
    }
}

SEC("lsm/path_mknod")
int BPF_PROG(trace_mknod, const struct path *dir, struct dentry *dentry,
             umode_t mode, unsigned int dev) {
    if (is_traced()) {
        print_path(dir, dentry);
    }

    return 0;
}

SEC("lsm/path_link")
int BPF_PROG(trace_link_dst, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
    if (is_traced()) {
        // TODO: Trace src of the hardlink
        print_path(new_dir, new_dentry);
    }

    return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(trace_rename,
             const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
  if (is_traced()) {
        print_path(old_dir, old_dentry);
        print_path(new_dir, new_dentry);
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(trace_open, struct file *file, int mask) {
    if (is_traced()) {
        print_path(&file->f_path, NULL);
    }

    return 0;
}

SEC("lsm/path_symlink") 
int BPF_PROG(restrict_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name) {
    if (is_traced()) {
        // TODO: Trace src of the hardlink
        print_path(dir, dentry);
    }

    return 0;
}
