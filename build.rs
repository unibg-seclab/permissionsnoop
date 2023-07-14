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

use std::env;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::Write;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

fn generate_kernel_defs() -> Result<(), Box<dyn std::error::Error>> {
  // Generate kernel definitions
  let mut cmd = Command::new("bpftool");
  cmd
    .arg("btf")
    .arg("dump")
    .arg("file")
    .arg("/sys/kernel/btf/vmlinux")
    .arg("format")
    .arg("c");
  let output = cmd.output().expect("Failed to run command");

  // Save the definitions to file
  let mut f = File::create("src/bpf/vmlinux.h")?;
  f.write_all(&output.stdout)?;

  Ok(())
}

const SRC: &str = "./src/bpf/permissionsnoop.bpf.c";

fn generate_skeleton() -> Result<(), Box<dyn std::error::Error>> {
  let build_profile = env::var("PROFILE")?;
  let arg = match &build_profile[..] {
    "debug" => "-DDEBUG",
    _ => "",
  };

  // It's unfortunate we cannot use `OUT_DIR` to store the generated skeleton.
  // Reasons are because the generated skeleton contains compiler attributes
  // that cannot be `include!()`ed via macro. And we cannot use the `#[path = "..."]`
  // trick either because you cannot yet `concat!(env!("OUT_DIR"), "/skel.rs")` inside
  // the path attribute either (see https://github.com/rust-lang/rust/pull/83366).
  //
  // However, there is hope! When the above feature stabilizes we can clean this
  // all up.
  create_dir_all("./src/bpf/.output")?;
  SkeletonBuilder::new()
    .clang_args(arg)
    .source(SRC)
    .build_and_generate("./src/bpf/.output/permissionsnoop.skel.rs")?;
  println!("cargo:rerun-if-changed={}", SRC);
  Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  generate_kernel_defs()?;
  generate_skeleton()?;
  Ok(())
}
