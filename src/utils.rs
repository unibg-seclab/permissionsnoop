use std::mem;
use std::str::from_utf8;

use anyhow::{anyhow, Result};

// include/uapi/linux/limits.h
const PATH_MAX: usize = 4096;

// include/linux/fs.h
const MAY_EXEC: u8 = 0x00000001;
const MAY_WRITE: u8 = 0x00000002;
const MAY_READ: u8 = 0x00000004;

const SRC_SIZE: usize = 32;

#[repr(C)]
struct PathEvent {
    src: [u8; SRC_SIZE],
    path: [u8; PATH_MAX],
    path_len: u32,
    permission: u8
}

pub fn get_event<'a>(data: &'a [u8]) -> Result<(&'static str, &'static str, u8)> {
    if data.len() != mem::size_of::<PathEvent>() {
        return Err(
            anyhow!(
                "Invalid size {} != {}",
                data.len(),
                mem::size_of::<PathEvent>()
            )
        );
    }

    let event = unsafe { &*(data.as_ptr() as *const PathEvent) };

    let src = from_utf8(&event.src).expect("Source should be UTF-8 encoded");
    let wrong_path = from_utf8(&event.path).expect("Path should be UTF-8 encoded");

    // Patch double printing issue
    let path = &wrong_path[..event.path_len as usize];

    Ok((src, path, event.permission))
}

pub fn get_permission_string(encoded_permission: u8) -> String {
    let mut permission = String::new();
    permission.push(if encoded_permission & MAY_READ != 0 { 'r' } else { '-' });
    permission.push(if encoded_permission & MAY_WRITE != 0 { 'w' } else { '-' });
    permission.push(if encoded_permission & MAY_EXEC != 0 { 'x' } else { '-' });

    permission
}
