//! Builds upstream liburing and its inline FFI with one private configuration per
//! Cargo output directory. Source caches and caller-owned source trees stay intact.

#[cfg(any(
    all(feature = "pre-release", feature = "stable"),
    not(any(feature = "pre-release", feature = "stable"))
))]
compile_error!("enable exactly one of the pre-release and stable features");

use std::{
    env,
    error::Error,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Output},
};

const REPOSITORY: &str = "https://github.com/axboe/liburing.git";
const RELEASE: &str = "liburing-2.15";
const OFFLINE_RELEASE: &str = "/root/.vcpkg/downloads/axboe-liburing-liburing-2.15.tar.gz";

type BuildResult<T> = Result<T, Box<dyn Error>>;

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

fn path_text(path: &Path) -> BuildResult<&str> {
    path.to_str()
        .ok_or_else(|| failure(format!("path is not UTF-8: {}", path.display())))
}

fn configure_word(word: &OsStr) -> BuildResult<&str> {
    let text = word
        .to_str()
        .ok_or_else(|| failure("compiler command contains a non-UTF-8 argument"))?;
    // Upstream configure expands its compiler command with shell word splitting.
    // Reject arguments it cannot preserve rather than probe a different compiler.
    if text.is_empty()
        || text
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '*' | '?' | '['))
    {
        return Err(failure(format!(
            "upstream configure cannot preserve compiler argument {text:?}"
        )));
    }
    Ok(text)
}

fn run(command: &mut Command, description: &str) -> BuildResult<Output> {
    let output = command
        .output()
        .map_err(|error| failure(format!("{description}: {error}")))?;
    if !output.status.success() {
        return Err(failure(format!(
            "{description} failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output)
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

fn target_root(manifest: &Path, output: &Path) -> BuildResult<PathBuf> {
    if let Some(configured) = env::var_os("CARGO_TARGET_DIR") {
        let path = PathBuf::from(configured);
        return Ok(if path.is_absolute() {
            path
        } else {
            manifest.join("../..").join(path)
        });
    }
    output
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            failure(format!(
                "cannot locate Cargo target directory above {}",
                output.display()
            ))
        })
}

fn verify_cached_ref(source: &Path, git_ref: &str) -> BuildResult<()> {
    if !source.join(".git").exists() {
        return Ok(());
    }
    let mut command = Command::new("git");
    command.arg("-C").arg(source);
    if git_ref == "master" {
        command.args(["symbolic-ref", "--short", "HEAD"]);
    } else {
        command.args(["describe", "--tags", "--exact-match", "HEAD"]);
    }
    let output = run(&mut command, "verify cached liburing reference")?;
    let actual = String::from_utf8_lossy(&output.stdout);
    if actual.trim() != git_ref {
        return Err(failure(format!(
            "liburing source cache reference mismatch at {}: expected {git_ref}, found {}",
            source.display(),
            actual.trim()
        )));
    }
    Ok(())
}

fn cached_source(target: &Path, git_ref: &str) -> BuildResult<PathBuf> {
    fs::create_dir_all(target).map_err(|error| {
        failure(format!(
            "create target directory {}: {error}",
            target.display()
        ))
    })?;
    let cache = target.join(format!("liburing-{git_ref}"));
    if is_source_tree(&cache) {
        verify_cached_ref(&cache, git_ref)?;
        return Ok(cache);
    }
    if cache.exists() {
        return Err(failure(format!(
            "invalid liburing source cache at {}",
            cache.display()
        )));
    }
    let staging = target.join(format!("liburing-{git_ref}.fetch-{}", std::process::id()));
    if staging.exists() {
        return Err(failure(format!(
            "source staging path already exists: {}",
            staging.display()
        )));
    }
    let output = Command::new("git")
        .args(["clone", "--depth", "1", "--branch", git_ref, REPOSITORY])
        .arg(&staging)
        .output()
        .map_err(|error| failure(format!("run git clone for liburing {git_ref}: {error}")))?;
    if !output.status.success() {
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(|error| {
                failure(format!(
                    "remove incomplete source staging directory {}: {error}",
                    staging.display()
                ))
            })?;
        }
        if git_ref != RELEASE || !Path::new(OFFLINE_RELEASE).is_file() {
            return Err(failure(format!(
                "clone liburing {git_ref} failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        fs::create_dir(&staging).map_err(|error| {
            failure(format!(
                "create offline extraction directory {}: {error}",
                staging.display()
            ))
        })?;
        run(
            Command::new("tar")
                .arg("-xzf")
                .arg(OFFLINE_RELEASE)
                .arg("--strip-components=1")
                .arg("-C")
                .arg(&staging),
            "extract offline liburing release",
        )?;
    }
    if !is_source_tree(&staging) {
        return Err(failure(format!(
            "fetched liburing source is incomplete: {}",
            staging.display()
        )));
    }
    verify_cached_ref(&staging, git_ref)?;
    if let Err(error) = fs::rename(&staging, &cache) {
        if !is_source_tree(&cache) {
            return Err(failure(format!(
                "publish liburing cache {}: {error}",
                cache.display()
            )));
        }
        verify_cached_ref(&cache, git_ref)?;
        fs::remove_dir_all(&staging).map_err(|error| {
            failure(format!(
                "remove duplicate source staging directory {}: {error}",
                staging.display()
            ))
        })?;
    }
    Ok(cache)
}

fn resolve_source(manifest: &Path, output: &Path, git_ref: &str) -> BuildResult<PathBuf> {
    if let Some(configured) = env::var_os("LIBURING_DIR") {
        let path = PathBuf::from(configured);
        if !is_source_tree(&path) {
            return Err(failure(format!(
                "LIBURING_DIR={} is not a liburing source tree",
                path.display()
            )));
        }
        return fs::canonicalize(&path)
            .map_err(|error| failure(format!("resolve LIBURING_DIR {}: {error}", path.display())));
    }
    for vendor in [
        manifest.join("vendor/liburing"),
        manifest.join("../../vendor/liburing"),
    ] {
        if is_source_tree(&vendor) {
            verify_cached_ref(&vendor, git_ref)?;
            return fs::canonicalize(&vendor).map_err(|error| {
                failure(format!(
                    "resolve vendored liburing {}: {error}",
                    vendor.display()
                ))
            });
        }
    }
    cached_source(&target_root(manifest, output)?, git_ref)
}

fn configure(source: &Path, output: &Path, compiler: &cc::Tool) -> BuildResult<PathBuf> {
    let build = output.join("liburing-build");
    fs::create_dir_all(&build).map_err(|error| {
        failure(format!(
            "create private liburing configuration directory {}: {error}",
            build.display()
        ))
    })?;
    let mut command = Command::new(source.join("configure"));
    let compiler_command = compiler.to_command();
    let mut words = vec![configure_word(compiler_command.get_program())?];
    for argument in compiler_command.get_args() {
        words.push(configure_word(argument)?);
    }
    command
        .current_dir(&build)
        .arg(format!("--cc={}", words.join(" ")))
        .arg("--use-libc")
        .env("CFLAGS", "");
    for (name, value) in compiler_command.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
    run(&mut command, "configure static liburing")?;
    for relative in [
        "config-host.h",
        "src/include/liburing/compat.h",
        "src/include/liburing/io_uring_version.h",
    ] {
        if !build.join(relative).is_file() {
            return Err(failure(format!(
                "configure did not create {}",
                build.join(relative).display()
            )));
        }
    }
    Ok(build)
}

fn header_directories(source: &Path, build: &Path, manifest: &Path) -> [PathBuf; 5] {
    [
        build.join("src/include"),
        source.join("src/include"),
        source.join("src"),
        build.to_path_buf(),
        manifest.join("csrc"),
    ]
}

fn compile_library(source: &Path, build: &Path, manifest: &Path) -> BuildResult<()> {
    let mut native = cc::Build::new();
    native
        .includes(header_directories(source, build, manifest))
        .define("_GNU_SOURCE", None)
        .define("_LARGEFILE_SOURCE", None)
        .define("_FILE_OFFSET_BITS", "64")
        .define("LIBURING_INTERNAL", None)
        .flag("-include")
        .flag(path_text(&build.join("config-host.h"))?)
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
    native
        .try_compile("uring_bundled")
        .map_err(|error| failure(format!("compile static liburing and C shim: {error}")))
}

fn generate_bindings(
    source: &Path,
    build: &Path,
    manifest: &Path,
    output: &Path,
    compiler: &cc::Tool,
) -> BuildResult<()> {
    let compiler_flags = compiler
        .args()
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .ok_or_else(|| failure("compiler flags contain a non-UTF-8 argument"))
        })
        .collect::<BuildResult<Vec<_>>>()?;
    // Environment include flags must not select different headers for the bindings and archive.
    let selected_headers = header_directories(source, build, manifest)
        .into_iter()
        .map(|path| format!("-I{}", path.display()));
    let bindings = bindgen::Builder::default()
        .header(path_text(&manifest.join("csrc/uring_shim.h"))?)
        .clang_args(selected_headers)
        .clang_args(compiler_flags)
        .clang_arg("-include")
        .clang_arg(path_text(&build.join("config-host.h"))?)
        .clang_arg("-D_GNU_SOURCE")
        .clang_arg("-D_LARGEFILE_SOURCE")
        .clang_arg("-D_FILE_OFFSET_BITS=64")
        .clang_arg("-DIOURINGINLINE=")
        .allowlist_function("io_uring_.*|uring_shim_.*")
        .allowlist_type("io_uring.*|__kernel_timespec")
        .allowlist_var("IORING_.*|IOSQE_.*|IO_URING_.*|LIBURING_.*")
        .blocklist_type("msghdr|sockaddr|iovec|sigset_t|__sigset_t")
        .blocklist_var("IORING_CQE_F_TSTAMP_HW|IORING_ZCRX_AREA_MASK")
        .blocklist_var(
            "IOSQE_(FIXED_FILE|IO_DRAIN|IO_LINK|IO_HARDLINK|ASYNC|BUFFER_SELECT|CQE_SKIP_SUCCESS)",
        )
        .prepend_enum_name(false)
        .derive_default(true)
        .rust_edition(bindgen::RustEdition::Edition2024)
        .wrap_unsafe_ops(true)
        .generate_comments(false)
        .layout_tests(false)
        .parse_callbacks(Box::new(
            bindgen::CargoCallbacks::new().rerun_on_header_files(false),
        ))
        .generate()
        .map_err(|error| {
            failure(format!(
                "generate liburing declarations from selected upstream headers: {error}"
            ))
        })?;
    bindings
        .write_to_file(output.join("bindings.rs"))
        .map_err(|error| {
            failure(format!(
                "write {}: {error}",
                output.join("bindings.rs").display()
            ))
        })
}

fn build() -> BuildResult<()> {
    for variable in ["LIBURING_DIR", "CARGO_TARGET_DIR"] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=csrc");
    let target_os = env::var("CARGO_CFG_TARGET_OS")
        .map_err(|error| failure(format!("read CARGO_CFG_TARGET_OS: {error}")))?;
    if target_os != "linux" {
        return Err(failure(format!(
            "liburing requires Linux, target OS is {target_os}"
        )));
    }
    let manifest = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| failure("CARGO_MANIFEST_DIR is not set"))?;
    let output = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| failure("OUT_DIR is not set"))?;
    let git_ref = if cfg!(feature = "stable") {
        RELEASE
    } else {
        "master"
    };
    let source = resolve_source(&manifest, &output, git_ref)?;
    for relative in ["configure", "Makefile.common", "src"] {
        println!("cargo:rerun-if-changed={}", source.join(relative).display());
    }
    let compiler = cc::Build::new()
        .try_get_compiler()
        .map_err(|error| failure(format!("resolve target C compiler: {error}")))?;
    let build = configure(&source, &output, &compiler)?;
    compile_library(&source, &build, &manifest)?;
    generate_bindings(&source, &build, &manifest, &output, &compiler)?;
    println!("cargo:include={}", source.join("src/include").display());
    println!("cargo:source={}", source.display());
    Ok(())
}

fn main() -> ExitCode {
    match build() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("liburing-sys native build failed: {error}");
            ExitCode::FAILURE
        }
    }
}
