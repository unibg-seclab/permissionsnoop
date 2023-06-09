use std::fs;
use std::{io::BufRead, io::BufReader};
use std::mem;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::str::from_utf8;

use anyhow::{anyhow, Result};
use criterion::black_box;
use clap::Parser;

mod bpf;
use bpf::opensnoop::*;

// include/uapi/linux/limits.h
const PATH_MAX: usize = 4096;

// include/uapi/asm-generic/fcntl.h
const O_RDONLY: u32 = 00000000;
const O_WRONLY: u32 = 00000001;
const O_RDWR: u32 = 00000001;

// #define O_CREAT		00000100	// create when does not exist
// #define O_EXCL		00000200	// create when does not exist, fails otherwise
// #define O_DIRECTORY	00200000
// #define __O_TMPFILE	020000000
// #define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)   // create unnamed temporary file

// ADDITIONAL NOTES:
// - Opening a file or directory with the O_PATH flag requires no permissions
//   on the object itself (but does require execute permission on the
//   directories in the path prefix).
// - An O_EXCL without O_CREAT has undefined behavior, unless working on a
//   block device
// - An O_TMPFILE without O_EXCL can be made permanent with linkat
// - An O_TRUNC without writing access mode has unspecified effect

const SRC_SIZE: usize = 32;

#[derive(Parser)]
struct Args {
    // TODO: Add src and permission arguments
    // TODO: Print events as they come or aggregate them
    // TODO: Export to CSV file
    #[clap(required(true), help("Command run inside the sandbox."))]
    command: Vec<String>,
}

#[repr(C)]
struct PathEvent {
    src: [u8; SRC_SIZE],
    path: [u8; PATH_MAX],
    path_len: u32,
    flags: u32,
}

fn is_lsm_bpf_available() -> Result<bool> {
    let lsm = fs::File::open("/sys/kernel/security/lsm")?;
    let mut line = String::new();
    let _len = BufReader::new(lsm)
        .read_line(&mut line);

    Ok(line.contains("bpf"))
}

fn has_necessary_capabilities() -> Result<bool> {
    let has_cap_sys_admin = caps::has_cap(
        None,
        caps::CapSet::Permitted,
        caps::Capability::CAP_SYS_ADMIN
    )?;
    let has_cap_sys_resource = caps::has_cap(
        None,
        caps::CapSet::Permitted,
        caps::Capability::CAP_SYS_RESOURCE
    )?;

    Ok(has_cap_sys_admin && has_cap_sys_resource)
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
    if data.len() != mem::size_of::<PathEvent>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<PathEvent>()
        );

        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const PathEvent) };
    let _src = from_utf8(&event.src)
        .expect("Source should be UTF-8 encoded");
    let path = from_utf8(&event.path)
        .expect("Path should be UTF-8 encoded");

    // TODO: Add write (and execute) permissions on the parent directory
    // whenever a file is beeing created

    // Extract string representation of the permission flags
    // TODO: Add support for exec permission
    let permission = {
        if event.flags & O_WRONLY != 0 {
            "-w"
        } else if event.flags & O_RDWR != 0 {
            "rw"
        } else {
            "r-"
        }
    };

    // Patch double printing issue
    println!("{} {}", &path[..event.path_len as usize], permission);

    return 0;
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Check availability of lsm bpf
    if !is_lsm_bpf_available()? {
        return Err(anyhow!("No LSM BPF support available"));
    }

    // Check necessary capabilities
    if !has_necessary_capabilities()? {
        return Err(anyhow!("Missing necessary capabilities (CAP_SYS_ADMIN and CAP_SYS_RESOURCE)"));
    }

    // Load BPF programs
    let mut skel = OpensnoopSkelBuilder::default().open()?.load()?;

    // Add ring buffer and associated callback
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(
            skel.maps().events(),
            move | data | { event_handler(data) }
        )?;
    let ring_buffer = builder.build()?;
   
    // Attach BPF programs
    skel.attach()?;

    // Drop permitted capabilities
    caps::clear(None, caps::CapSet::Permitted)?;

    // Define tracing closure
    let enable_tracing = move || {
        attach_tracer();
        Ok(())
    };

    // Run command to trace
    let program = &args.command[0];
    let arguments = &args.command[1..];
    unsafe {
        let mut child = Command::new(program)
            .args(arguments)
            .pre_exec(enable_tracing)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        while child.try_wait()?.is_none() {
            // Use reasonable duration to avoid busy waiting
            ring_buffer.poll(core::time::Duration::from_millis(5))?;
        }
    }

    Ok(())
}
