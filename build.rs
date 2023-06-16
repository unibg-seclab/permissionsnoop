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
