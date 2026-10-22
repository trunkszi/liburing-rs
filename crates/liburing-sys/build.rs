//! Builds upstream liburing and its inline FFI with one private configuration per
//! Cargo output directory. Source caches and caller-owned source trees stay intact.

#[cfg(any(
    all(feature = "pre-release", feature = "stable"),
    not(any(feature = "pre-release", feature = "stable"))
))]
compile_error!("enable exactly one of the pre-release and stable features");

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const REPOSITORY: &str = "https://github.com/axboe/liburing.git";
const RELEASE: &str = "liburing-2.15";
const OFFLINE_RELEASE: &str = "/root/.vcpkg/downloads/axboe-liburing-liburing-2.15.tar.gz";

fn run(command: &mut Command, description: &str) -> Output {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{description}: {error}"));
    assert!(
        output.status.success(),
        "{description} failed ({}):\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn is_source_tree(path: &Path) -> bool {
    [
        "configure",
        "src/include/liburing.h",
        "src/setup.c",
        "src/Makefile",
    ]
    .iter()
    .all(|relative| path.join(relative).is_file())
}

fn target_root(manifest: &Path, output: &Path) -> PathBuf {
    if let Some(configured) = env::var_os("CARGO_TARGET_DIR") {
        let path = PathBuf::from(configured);
        return if path.is_absolute() {
            path
        } else {
            manifest.join("../..").join(path)
        };
    }
    output
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("Cargo target directory above OUT_DIR")
        .to_path_buf()
}

fn verify_cached_ref(source: &Path, git_ref: &str) {
    if !source.join(".git").exists() {
        return;
    }
    let mut command = Command::new("git");
    command.arg("-C").arg(source);
    if git_ref == "master" {
        command.args(["symbolic-ref", "--short", "HEAD"]);
    } else {
        command.args(["describe", "--tags", "--exact-match", "HEAD"]);
    }
    let output = run(&mut command, "verify cached liburing reference");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        git_ref,
        "liburing source cache reference mismatch at {}",
        source.display()
    );
}

fn cached_source(target: &Path, git_ref: &str) -> PathBuf {
    fs::create_dir_all(target).expect("create target directory");
    let cache = target.join(format!("liburing-{git_ref}"));
    if is_source_tree(&cache) {
        verify_cached_ref(&cache, git_ref);
        return cache;
    }
    assert!(
        !cache.exists(),
        "invalid liburing source cache at {}",
        cache.display()
    );
    let staging = target.join(format!("liburing-{git_ref}.fetch-{}", std::process::id()));
    assert!(!staging.exists(), "source staging path already exists");
    let output = Command::new("git")
        .args(["clone", "--depth", "1", "--branch", git_ref, REPOSITORY])
        .arg(&staging)
        .output()
        .expect("run git clone for liburing");
    if !output.status.success() {
        if staging.exists() {
            fs::remove_dir_all(&staging).expect("remove incomplete source staging directory");
        }
        assert!(
            git_ref == RELEASE && Path::new(OFFLINE_RELEASE).is_file(),
            "clone liburing {git_ref} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::create_dir(&staging).expect("create offline extraction directory");
        run(
            Command::new("tar")
                .arg("-xzf")
                .arg(OFFLINE_RELEASE)
                .arg("--strip-components=1")
                .arg("-C")
                .arg(&staging),
            "extract offline liburing release",
        );
    }
    assert!(
        is_source_tree(&staging),
        "fetched liburing source is incomplete"
    );
    verify_cached_ref(&staging, git_ref);
    if let Err(error) = fs::rename(&staging, &cache) {
        assert!(
            is_source_tree(&cache),
            "publish liburing cache {}: {error}",
            cache.display()
        );
        verify_cached_ref(&cache, git_ref);
        fs::remove_dir_all(&staging).expect("remove duplicate source staging directory");
    }
    cache
}

fn resolve_source(manifest: &Path, output: &Path, git_ref: &str) -> PathBuf {
    if let Some(configured) = env::var_os("LIBURING_DIR") {
        let path = PathBuf::from(configured);
        assert!(
            is_source_tree(&path),
            "LIBURING_DIR={} is not a liburing source tree",
            path.display()
        );
        return fs::canonicalize(path).expect("resolve LIBURING_DIR");
    }
    for vendor in [
        manifest.join("vendor/liburing"),
        manifest.join("../../vendor/liburing"),
    ] {
        if is_source_tree(&vendor) {
            verify_cached_ref(&vendor, git_ref);
            return fs::canonicalize(vendor).expect("resolve vendored liburing");
        }
    }
    cached_source(&target_root(manifest, output), git_ref)
}

fn configure(source: &Path, output: &Path, compiler: &cc::Tool) -> PathBuf {
    let build = output.join("liburing-build");
    fs::create_dir_all(&build).expect("create private liburing configuration directory");
    let mut command = Command::new(source.join("configure"));
    command
        .current_dir(&build)
        .arg(format!("--cc={}", compiler.path().display()))
        .arg("--use-libc");
    // cc supplies target-specific options as well as Cargo's CFLAGS overrides.
    // Configure uses these same options when probing the target compiler.
    let flags = compiler
        .args()
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    command.env("CFLAGS", flags);
    run(&mut command, "configure static liburing");
    for relative in [
        "config-host.h",
        "src/include/liburing/compat.h",
        "src/include/liburing/io_uring_version.h",
    ] {
        assert!(
            build.join(relative).is_file(),
            "configure did not create {relative}"
        );
    }
    build
}

fn compile_library(source: &Path, build: &Path, manifest: &Path) {
    let mut native = cc::Build::new();
    native
        .include(build.join("src/include"))
        .include(source.join("src/include"))
        .include(source.join("src"))
        .include(build)
        .define("_GNU_SOURCE", None)
        .define("_LARGEFILE_SOURCE", None)
        .define("_FILE_OFFSET_BITS", "64")
        .define("LIBURING_INTERNAL", None)
        .flag("-include")
        .flag(
            build
                .join("config-host.h")
                .to_str()
                .expect("UTF-8 config path"),
        )
        .flag_if_supported("-std=gnu11")
        .warnings(false)
        .pic(true);
    for filename in [
        "setup.c",
        "queue.c",
        "register.c",
        "syscall.c",
        "version.c",
        "ffi.c",
    ] {
        native.file(source.join("src").join(filename));
    }
    // New upstream versions may split buffer registration out of register.c.
    if source.join("src/buf.c").is_file() {
        native.file(source.join("src/buf.c"));
    }
    native.file(manifest.join("csrc/uring_shim.c"));
    native.compile("uring_bundled");
}

fn generate_bindings(source: &Path, build: &Path, manifest: &Path, output: &Path) {
    let bindings = bindgen::Builder::default()
        .header(
            manifest
                .join("csrc/uring_shim.h")
                .to_str()
                .expect("UTF-8 shim path"),
        )
        .clang_arg(format!("-I{}", build.join("src/include").display()))
        .clang_arg(format!("-I{}", source.join("src/include").display()))
        .clang_arg("-D_GNU_SOURCE")
        .clang_arg("-DIOURINGINLINE=")
        .allowlist_function("io_uring_.*|uring_shim_.*")
        .allowlist_type("io_uring.*|__kernel_timespec")
        .allowlist_var("IORING_.*|IOSQE_.*|IO_URING_.*|LIBURING_.*")
        .blocklist_type("msghdr|sockaddr|iovec|sigset_t|__sigset_t")
        .prepend_enum_name(false)
        .derive_default(true)
        .rust_edition(bindgen::RustEdition::Edition2024)
        .wrap_unsafe_ops(true)
        .generate_comments(false)
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("generate liburing declarations from selected upstream headers");
    bindings
        .write_to_file(output.join("bindings.rs"))
        .expect("write bindings.rs");
}

fn main() {
    for variable in ["LIBURING_DIR", "CARGO_TARGET_DIR"] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=csrc");
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "liburing requires Linux"
    );
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let git_ref = if cfg!(feature = "stable") {
        RELEASE
    } else {
        "master"
    };
    let source = resolve_source(&manifest, &output, git_ref);
    for relative in ["configure", "Makefile.common", "src"] {
        println!("cargo:rerun-if-changed={}", source.join(relative).display());
    }
    let compiler = cc::Build::new().get_compiler();
    let build = configure(&source, &output, &compiler);
    compile_library(&source, &build, &manifest);
    generate_bindings(&source, &build, &manifest, &output);
    println!("cargo:include={}", source.join("src/include").display());
    println!("cargo:source={}", source.display());
}
