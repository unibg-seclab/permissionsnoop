use std::collections::HashMap;

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use anyhow::Result;
use clap::Parser;
use criterion::black_box;

mod bpf;
use bpf::load_bpf_programs_and_maps;
mod utils;
use utils::{get_event, get_permission_string};

use libbpf_rs::libbpf_sys::{bpf_map_update_elem, BPF_ANY};

use libc::c_void;

static mut PATH_PERMISSIONS: Vec<HashMap<&str, u8>> = vec![];

#[derive(Parser)]
#[command(
    about = "eBPF-based security observability tool to trace filesystem-related events",
    long_about = None
)]
struct Args {
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "Print aggregate permission on exit"
    )]
    aggregate: bool,
    #[arg(
        required = true,
        help = "A command or a sequence of space-separated thread identifiers"
    )]
    component: Vec<String>,
}

/*
 * ProcessCommand uprobe attachment point
*/
#[no_mangle]
#[inline(never)]
pub extern "C" fn attach_tracer() {
    black_box(420);
}

fn ref_to_voidp<T>(r: &T) -> *const c_void {
    r as *const T as *const c_void
}

fn event_handler(data: &[u8]) -> i32 {
    let res = get_event(&data);
    if let Err(msg) = res {
        eprintln!("{}", msg);
        return 1;
    }

    let (src, path, curr_permission) = res.unwrap();

    match unsafe { &mut PATH_PERMISSIONS.get_mut(0) } {
        Some(path_permissions) => {
            // Update data structure to aggregate path permissions
            match path_permissions.get(path) {
                Some(permission) => {
                    let new_permission = permission | curr_permission;
                    path_permissions.insert(path, new_permission);
                }
                None => {
                    path_permissions.insert(path, curr_permission);
                }
            }
        }
        None => {
            // Print path event
            let permission = get_permission_string(curr_permission);
            println!("{},\"{}\",{}", src, path, permission);
        }
    }

    return 0;
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.aggregate {
        // Initialize data structure to aggregate path permissions
        unsafe {
            PATH_PERMISSIONS.push(HashMap::new());
        }
    }

    let (mut skel, ring_buffer) = load_bpf_programs_and_maps(event_handler)?;

    // Print header
    match args.aggregate {
        true => println!("Path,Permission"),
        false => println!("Source,Path,Permission"),
    }

    let is_command: bool = match args.component[0].parse::<u32>() {
        Ok(_) => false,
        Err(_) => true,
    };

    if is_command {
        // Closure to enable tracing of the component before its execution
        let enable_tracing = move || {
            attach_tracer();
            Ok(())
        };

        // Run command to trace
        let program = &args.component[0];
        let arguments = &args.component[1..];

        let mut child;
        unsafe {
            child = Command::new(program)
                .args(arguments)
                .pre_exec(enable_tracing)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
        }
        // Listen for events while waiting for the child process to exit
        while child.try_wait()?.is_none() {
            // Use reasonable duration to avoid busy waiting
            ring_buffer.poll(core::time::Duration::from_millis(5))?;
        }
    } else {
        // Retrive the thread identifier eBPF map
        let tid_map_fd = skel.maps_mut().tid_map().fd();
        // lookup hit placeholder
        let t_hit: u8 = 1;
        let t_hit_ptr: *const c_void = ref_to_voidp(&t_hit);

        // Attach the tracer to all the pids
        let components_i = args.component.iter();
        for pid in components_i {
            match pid.parse::<u32>() {
                Ok(pidv) => {
                    println!("Attaching policy to thread {:?}", pidv);
                    unsafe {
                        let t_entry_ptr: *const c_void = ref_to_voidp(&pidv);
                        let err =
                            bpf_map_update_elem(tid_map_fd, t_entry_ptr, t_hit_ptr, BPF_ANY as u64);
                        if err != 0 {
                            panic!("Failed insertion in host_map {:?}", err);
                        }
                    }
                }
                Err(_) => panic!("Component {:?} is not a valid thread identifier", pid),
            };
        }
        // keep polling
        loop {
            ring_buffer.poll(core::time::Duration::from_millis(5))?;
        }
    }

    // Print aggregated path permissions
    if let Some(path_permissions) = unsafe { PATH_PERMISSIONS.get(0) } {
        // Sort results by path
        let mut items = Vec::from_iter(path_permissions.iter());
        items.sort();
        for (path, encoded_permission) in items {
            let permission = get_permission_string(*encoded_permission);
            println!("\"{}\",{}", path, permission);
        }
    }

    Ok(())
}
