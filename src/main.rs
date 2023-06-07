use std::{io::BufRead, io::BufReader};
use std::fs;
use std::mem;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::str::from_utf8;

use anyhow::{anyhow, Result};
use criterion::black_box;
use clap::Parser;

mod bpf;
use bpf::opensnoop::*;

const PATH_SIZE: usize = 4096;

#[derive(Parser)]
struct Args {
    #[clap(required(true), help("Command run inside the sandbox."))]
    command: Vec<String>,
}

#[repr(C)]
struct PathEvent {
    path: [u8; PATH_SIZE],
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
    let path = from_utf8(&event.path)
        .expect("Path should be UTF-8 encoded");
    // TODO: Fix double printing issue
    println!("{} {}", path.len(), path);

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
            .spawn()?;

        while child.try_wait()?.is_none() {
            // Use reasonable duration to avoid busy waiting
            ring_buffer.poll(core::time::Duration::from_millis(5))?;
        }
    }

    Ok(())
}
