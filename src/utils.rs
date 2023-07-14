// Copyright (c) 2023 Unibg Seclab (https://seclab.unibg.it)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use anyhow::{anyhow, Result};
use std::mem;
use std::str::{from_utf8, Utf8Error};

// include/uapi/linux/limits.h
const PATH_MAX: usize = 4096;

// include/linux/fs.h
const MAY_EXEC: u8 = 0x00000001;
const MAY_WRITE: u8 = 0x00000002;
const MAY_READ: u8 = 0x00000004;

const SRC_SIZE: usize = 32;

#[repr(C)]
struct PathEvent {
    permission: u8,
    path_len: u32,
    src: [u8; SRC_SIZE],
    path: [u8; PATH_MAX],
}

fn read_event_str(bstr: &[u8]) -> Result<&str, Utf8Error> {
    let index = bstr.iter().position(|&r| r == 0).unwrap();
    let tsrc = &bstr[..index];
    from_utf8(&tsrc)
}

pub fn get_event<'a>(data: &'a [u8]) -> Result<(&'static str, &'static str, u8)> {
    if data.len() != mem::size_of::<PathEvent>() {
        return Err(anyhow!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<PathEvent>()
        ));
    }

    let event = unsafe { &*(data.as_ptr() as *const PathEvent) };

    //    println!("{}", event.path_len);
    let src = read_event_str(&event.src).expect("Src should be UTF8");
    let path = read_event_str(&event.path).expect("Path should be UTF8");

    Ok((src, path, event.permission))
}

pub fn get_permission_string(encoded_permission: u8) -> String {
    let mut permission = String::new();
    permission.push(if encoded_permission & MAY_READ != 0 {
        'r'
    } else {
        '-'
    });
    permission.push(if encoded_permission & MAY_WRITE != 0 {
        'w'
    } else {
        '-'
    });
    permission.push(if encoded_permission & MAY_EXEC != 0 {
        'x'
    } else {
        '-'
    });

    permission
}
