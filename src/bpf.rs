use std::fs;
use std::{io::BufRead, io::BufReader};

use anyhow::{anyhow, Result};
use libbpf_rs::RingBuffer;

#[path = "bpf/.output/permissionsnoop.skel.rs"]
pub mod permissionsnoop;
use permissionsnoop::*;

pub fn is_lsm_bpf_available() -> Result<bool> {
    let lsm = fs::File::open("/sys/kernel/security/lsm")?;
    let mut line = String::new();
    let _len = BufReader::new(lsm)
        .read_line(&mut line);

    Ok(line.contains("bpf"))
}

pub fn has_necessary_capabilities() -> Result<bool> {
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

pub fn load_bpf_programs_and_maps(
    event_handler: fn(&[u8]
) -> i32) -> Result<(PermissionsnoopSkel<'static>, RingBuffer<'static>)> {
    // Check availability of lsm bpf
    if !is_lsm_bpf_available()? {
        return Err(anyhow!("No LSM BPF support available"));
    }

    // Check necessary capabilities
    if !has_necessary_capabilities()? {
        return Err(anyhow!("Missing necessary capabilities (CAP_SYS_ADMIN and CAP_SYS_RESOURCE)"));
    }

    // Load BPF programs
    let mut skel = PermissionsnoopSkelBuilder::default().open()?.load()?;

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

    Ok((skel, ring_buffer))
}
