extern crate cc;

fn main() -> Result<(), std::io::Error> {
    use std::{io, fs, env, process::Command, path::PathBuf};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_file as symlink;

    let path = env::current_dir()?.join("newhope/ref");
    let out_dir = env::var_os("OUT_DIR").map(PathBuf::from).unwrap();

    let mut build = cc::Build::new();
    build
        .include("newhope/ref")
        .file(path.join("poly.c"))
        .file(path.join("reduce.c"))
        .file(path.join("fips202.c"))
        .file(path.join("verify.c"))
        .file(path.join("cpapke.c"))
        .file(path.join("ntt.c"))
        .file(path.join("precomp.c"))
        .force_frame_pointer(false)
        .opt_level(3)
        .pic(true)
        .target("native")
        .flag("-no-pie");

    symlink(path.join("cpakem.h"), path.join("api.h"))
        .or_else(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Ok(()),
            e => Err(e),
        })?;

    let mut p_build = build.clone();
    p_build.file(path.join("cpakem.c"));

    let mut p_512 = p_build.clone();
    p_512
        .define("NEWHOPE_N", Some("512"))
        .compile("libcpakem512.a");
    let _ = Command::new("objcopy")
        .current_dir(out_dir.clone())
        .arg("--prefix-symbols=p512_")
        .arg("libcpakem512.a")
        .output()
        .unwrap();
    let _ = Command::new("objcopy")
        .current_dir(out_dir.clone())
        .arg("--redefine-sym")
        .arg("p512___stack_chk_fail=__stack_chk_fail")
        .arg("--redefine-sym")
        .arg("p512_randombytes=randombytes")
        .arg("libcpakem512.a")
        .output()
        .unwrap();

    let mut p_1024 = p_build;
    p_1024
        .define("NEWHOPE_N", Some("1024"))
        .compile("libcpakem1024.a");
    let _ = Command::new("objcopy")
        .current_dir(out_dir.clone())
        .arg("--prefix-symbols=p1024_")
        .arg("libcpakem1024.a")
        .output()
        .unwrap();
    let _ = Command::new("objcopy")
        .current_dir(out_dir.clone())
        .arg("--redefine-sym")
        .arg("p1024___stack_chk_fail=__stack_chk_fail")
        .arg("--redefine-sym")
        .arg("p1024_randombytes=randombytes")
        .arg("libcpakem1024.a")
        .output()
        .unwrap();

    symlink(path.join("ccakem.h"), path.join("api.h"))
        .or_else(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Ok(()),
            e => Err(e),
        })?;

    let mut c_build = build;
    c_build.file(path.join("ccakem.c"));

    let mut c_512 = c_build.clone();
    c_512
        .define("NEWHOPE_N", Some("512"))
        .compile("libccakem512.a");
    let _ = Command::new("objcopy")
        .current_dir(out_dir.clone())
        .arg("--prefix-symbols=c512_")
        .arg("libccakem512.a")
        .output()
        .unwrap();
    let _ = Command::new("objcopy")
        .current_dir(out_dir.clone())
        .arg("--redefine-sym")
        .arg("c512___stack_chk_fail=__stack_chk_fail")
        .arg("--redefine-sym")
        .arg("c512_randombytes=randombytes")
        .arg("libccakem512.a")
        .output()
        .unwrap();

    let mut c_1024 = c_build;
    c_1024
        .define("NEWHOPE_N", Some("1024"))
        .compile("libccakem1024.a");
    let _ = Command::new("objcopy")
        .current_dir(out_dir.clone())
        .arg("--prefix-symbols=c1024_")
        .arg("libccakem1024.a")
        .output()
        .unwrap();
    let _ = Command::new("objcopy")
        .current_dir(out_dir.clone())
        .arg("--redefine-sym")
        .arg("c1024___stack_chk_fail=__stack_chk_fail")
        .arg("--redefine-sym")
        .arg("c1024_randombytes=randombytes")
        .arg("libccakem1024.a")
        .output()
        .unwrap();

    fs::remove_file(path.join("api.h"))?;
    Ok(())
}
