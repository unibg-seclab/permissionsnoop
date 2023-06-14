use std::collections::HashMap;

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use anyhow::Result;
use criterion::black_box;
use clap::Parser;

mod bpf;
use bpf::load_bpf_programs_and_maps;
mod utils;
use utils::{get_event, get_permission_string};

static mut PATH_PERMISSIONS: Vec<HashMap<&str, u8>> = vec![];

#[derive(Parser)]
struct Args {
    #[clap(
        short('a'),
        long("--aggregate"),
        help("Print aggregate permission on exit. Otherwise, print events as \
                they come with only the current permission")
    )]
    aggregate: bool,
    #[clap(required(true), help("Command run inside the sandbox."))]
    command: Vec<String>,
}

/*
 * Uprobe attachment point
*/
#[no_mangle]
#[inline(never)]
pub extern "C" fn attach_tracer() {
    black_box(420);
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
                },
                None => {
                    path_permissions.insert(path, curr_permission);
                }
            }
        },
        None => {
            // Print path event
            let permission = get_permission_string(curr_permission);
            println!("{},{},{}", src, path, permission);
        }
    }

    return 0;
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.aggregate {
        // Initialize data structure to aggregate path permissions
        unsafe { PATH_PERMISSIONS.push(HashMap::new()); }
    }

    let (_skel, ring_buffer) = load_bpf_programs_and_maps(event_handler)?;

    // Closure to enable tracing of the command before its execution
    let enable_tracing = move || {
        attach_tracer();
        Ok(())
    };

    // Run command to trace
    let program = &args.command[0];
    let arguments = &args.command[1..];
    let mut child;
    unsafe {
        child = Command::new(program)
            .args(arguments)
            .pre_exec(enable_tracing)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    }

    // Print header
    match args.aggregate {
        true => println!("Path,Permission"),
        false => println!("Source,Path,Permission"),
    }

    // Listen for events while waiting for the child process to exit
    while child.try_wait()?.is_none() {
        // Use reasonable duration to avoid busy waiting
        ring_buffer.poll(core::time::Duration::from_millis(5))?;
    }

    // Print aggregated path permissions
    // TODO: Sort results by path
    if let Some(path_permissions) = unsafe { PATH_PERMISSIONS.get(0) } {
        for (path, encoded_permission) in path_permissions {
            let permission = get_permission_string(*encoded_permission);
            println!("{},{}", path, permission);
        }
    }

    Ok(())
}
