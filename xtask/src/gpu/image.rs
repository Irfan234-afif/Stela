//! The image's own Vulkan drivers on the build host, after `cargo xtask gpu
//! nvk` built them: every unit of the image's RADV, ANV, shared Mesa code,
//! libdrm_amdgpu, stand-ins and C library compiled again from the command
//! the image compiled it with, with only the target changed from the
//! image's COFF one to Linux's, linked into a static Linux program with the
//! image's C library under the drivers and `image/host.c` under that, and
//! run over Mesa's DRM shim with amdgpu's, xe's and i915's no-op shims
//! (`image/vulkan_device.c`).
//!
//! The hosted tests (`radv-test`, `anv-test`) build Mesa again for the host,
//! with the host's C library and the host's probe results; what the image
//! drops (a probe define such as `HAVE_DLADDR`) or answers differently (a
//! C library call that fails, or answers a fixed value) never shows there.
//! Here it does: the image's defines, the image's C library and the image's
//! objects but for the object format and calling convention.
use super::nvk::{LINKED, Unit, compile};
use super::support::{build_directory, gpu, third_party};
use super::toolchain::{self, Toolchain};
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// The image's C target and Linux's, which the units are compiled for here.
const IMAGE_TARGET: &str = "--target=x86_64-pc-cygwin";
const LINUX_TARGET: &str = "--target=x86_64-unknown-linux-gnu";
/// Flags of the image's target that only a COFF object takes.
const COFF_ONLY: [&str; 2] = ["-mno-stack-arg-probe", "-mno-incremental-linker-compatible"];
// What still differs from the image after the retarget, from Clang's
// predefined macros for the two targets: `__ELF__`, `__gnu_linux__`, `linux`
// and `__unix` are Linux's only, and `wchar_t` is 4 bytes here and 2 in the
// image. No unit the image links reads any of them.

/// Units the program leaves out, by a part of their object's name: NVK and
/// NAK, which need the image's Rust, and the Metal compiler, which needs its
/// LLVM.
const LEFT_OUT: [&str; 9] = [
    "src_nouveau_",
    "stela_nvkcl",
    "stela_nv_cubin",
    "stela_nir_options",
    "stela_submit_thread",
    "stela_air_",
    "stela_metal_",
    "stela_threadgroup",
    "src_compiler_rust_",
];

/// Each run's GPUs, as kernel driver and device: amdgpu's by name, xe's
/// and i915's by PCI device ID. RADV runs on amdgpu, ANV on xe and i915.
const RUNS: [&[&str]; 13] = [
    &["amdgpu:raphael_mendocino"],
    &["amdgpu:navi21"],
    &["amdgpu:polaris10", "amdgpu:polaris10"],
    &["xe:9a49"],
    &["xe:46a6"],
    &["xe:7d55"],
    &["xe:56a0"],
    &["xe:e20b"],
    &["i915:9a49"],
    &["i915:46a6"],
    &["i915:7d55"],
    &["i915:56a0"],
    // An AMD and an Intel GPU in one image, each driver on its own.
    &["amdgpu:navi21", "xe:56a0"],
];

pub fn test(jobs: u16) -> Result<()> {
    let toolchain = toolchain::discover()?;
    let image = build_directory("nvk");
    let build = image.join("build");
    let drivers = fs::read_to_string(image.join(LINKED))
        .context("the image's Mesa is not built: run `cargo xtask gpu nvk`")?;
    for driver in ["amd", "intel"] {
        if !drivers.lines().any(|linked| linked == driver) {
            bail!(
                "the image's Mesa was built without Vulkan driver {driver}: build it with the \
                 host tools RADV and ANV need (`cargo xtask gpu nvk`)"
            );
        }
    }
    let directory = build_directory("image-host");
    let objects = directory.join("objects");
    fs::create_dir_all(&objects)?;

    let mut whole = Vec::new();
    let mut lazy = Vec::new();
    for (list, linked) in [
        ("libstela-vulkan.rsp", &mut whole),
        ("libstela-nvk.rsp", &mut lazy),
    ] {
        for object in members(&image.join(list))? {
            let name = object
                .file_name()
                .context("an archive member")?
                .to_string_lossy()
                .into_owned();
            if LEFT_OUT.iter().any(|part| name.contains(part)) {
                continue;
            }
            linked.push(Unit {
                output: objects.join(&name),
                arguments: retargeted(&record(&object)?),
            });
        }
    }
    let own = own_units(&image, &objects)?;
    let all: Vec<Unit> = own
        .iter()
        .chain(&whole)
        .chain(&lazy)
        .map(|unit| Unit {
            output: unit.output.clone(),
            arguments: unit.arguments.clone(),
        })
        .collect();
    println!("compiling {} units of the image for Linux", all.len());
    compile(&toolchain.clang, &build, &all, jobs)?;
    // The xe shim's own stat, which the hosted test puts before the host C
    // library's, would take the image C library's place here.
    let xe = objects.join("image_xe_noop_drm_shim.o");
    crate::tools::exec(
        Command::new(llvm_tool(&toolchain, "llvm-objcopy"))
            .args(["--redefine-sym", "stat=image_xe_shim_stat"])
            .args(["--redefine-sym", "stat64=image_xe_shim_stat64"])
            .arg(&xe),
    )?;
    let program = link(&toolchain, &directory, &image, &own, &whole, &lazy)?;
    run(&program, &directory)
}

/// The objects an archive's response file lists.
fn members(list: &Path) -> Result<Vec<PathBuf>> {
    Ok(fs::read_to_string(list)
        .with_context(|| format!("reading {}", list.display()))?
        .lines()
        .map(|line| PathBuf::from(line.trim().trim_matches('"')))
        .filter(|path| !path.as_os_str().is_empty())
        .collect())
}

/// The arguments the image compiled `object` with, from its record.
fn record(object: &Path) -> Result<Vec<String>> {
    let record = object.with_extension("command");
    Ok(fs::read_to_string(&record)
        .with_context(|| format!("reading {}", record.display()))?
        .split('\n')
        .map(str::to_owned)
        .collect())
}

/// The image's arguments for Linux's target: the target and the flags only
/// a COFF object takes are all that change.
fn retargeted(arguments: &[String]) -> Vec<String> {
    arguments
        .iter()
        .filter(|word| !COFF_ONLY.contains(&word.as_str()))
        .map(|word| {
            if word == IMAGE_TARGET {
                LINUX_TARGET.to_owned()
            } else {
                word.clone()
            }
        })
        .collect()
}

/// The program's own units, each compiled with a driver stand-in's
/// arguments, the stand-in's source replaced: the test, the host, Mesa's
/// DRM shim and the no-op shims of amdgpu and xe. The shims model the
/// kernel, so what they read of the environment and the clock is the
/// host's.
fn own_units(image: &Path, objects: &Path) -> Result<Vec<Unit>> {
    let units = image.join("objects");
    let radv = record(&units.join("stela_radv_submit.o"))?;
    let anv = record(&units.join("stela_anv_nir_options.o"))?;
    let libc = record(&units.join("libc_libc.o"))?;
    // The C++ runtime the image's LLVM archive carries: allocation, the
    // compiler's runtime calls and the null exception_ptr.
    let runtime = Unit {
        output: objects.join("image_llvm_runtime.o"),
        arguments: retargeted(&record(
            &build_directory("llvm").join("objects/llvm_runtime_cpp.o"),
        )?),
    };
    let mesa = third_party("mesa").join("src");
    let own = gpu().join("image");
    let like = |model: &[String], source: PathBuf, name: &str, defines: &[&str]| -> Unit {
        let mut arguments: Vec<String> = retargeted(model)
            .into_iter()
            .map(|word| {
                if word.ends_with(".c") && Path::new(&word).is_file() {
                    source.display().to_string()
                } else {
                    word
                }
            })
            .collect();
        arguments.extend(defines.iter().map(|define| format!("-D{define}")));
        // The shims' Linux headers the image's C library lacks.
        if name.contains("shim") {
            arguments.push(format!("-I{}", own.join("include").display()));
            arguments.push(format!("-include{}", own.join("include/shim.h").display()));
        }
        Unit {
            output: objects.join(format!("image_{name}.o")),
            arguments,
        }
    };
    Ok(vec![
        runtime,
        like(&radv, own.join("vulkan_device.c"), "vulkan_device", &[]),
        like(&radv, own.join("host.c"), "host", &[]),
        like(
            &libc,
            gpu().join("compat/libc/tests/string.c"),
            "string",
            &[],
        ),
        like(
            &radv,
            mesa.join("drm-shim/device.c"),
            "drm_shim_device",
            &["drm_shim_driver_init=image_shim_driver_init"],
        ),
        like(
            &radv,
            mesa.join("amd/drm-shim/amdgpu_noop_drm_shim.c"),
            "amdgpu_noop_drm_shim",
            &[
                "drm_shim_driver_init=amdgpu_shim_driver_init",
                "os_get_option=image_host_option",
            ],
        ),
        like(
            &radv,
            mesa.join("amd/common/amdgpu_devices.c"),
            "amdgpu_devices",
            &[],
        ),
        like(
            &anv,
            gpu().join("intel/hosted/xe_noop_drm_shim.c"),
            "xe_noop_drm_shim",
            &[
                "drm_shim_driver_init=xe_shim_driver_init",
                "getenv=image_host_option",
                "clock_gettime=image_host_clock_gettime",
            ],
        ),
        like(
            &anv,
            mesa.join("intel/tools/intel_noop_drm_shim.c"),
            "i915_noop_drm_shim",
            &[
                "drm_shim_driver_init=i915_shim_driver_init",
                "os_get_option=image_host_option",
                "intel_device_info_from_json=image_no_device_json",
            ],
        ),
    ])
}

/// An LLVM tool beside the toolchain's Clang, else on PATH.
fn llvm_tool(toolchain: &Toolchain, name: &str) -> PathBuf {
    toolchain
        .clang
        .parent()
        .map(|directory| directory.join(name))
        .filter(|tool| tool.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Links the static program: its own objects and the drivers' whole, the
/// rest as an archive, as the image links them, then the regex units and
/// libc++ of the machine Mesa was configured for, built on the image's C
/// library, and the compiler's builtins.
fn link(
    toolchain: &Toolchain,
    directory: &Path,
    image: &Path,
    own: &[Unit],
    whole: &[Unit],
    lazy: &[Unit],
) -> Result<PathBuf> {
    let archive = directory.join("libimage-lazy.a");
    super::support::archive(
        &toolchain.archiver,
        &archive,
        lazy.iter().map(|unit| &unit.output),
    )?;
    let sysroot = image.join("sysroot");
    let support: Vec<PathBuf> = super::nvk::REGEX
        .iter()
        .map(|name| sysroot.join("objects").join(format!("{name}.o")))
        .collect();
    let builtins = super::support::capture(Command::new(&toolchain.clang).args([
        LINUX_TARGET,
        "--rtlib=compiler-rt",
        "-print-libgcc-file-name",
    ]))?;
    let program = directory.join("image_device");
    crate::tools::exec(
        Command::new(&toolchain.linker)
            .args(["-static", "--no-pie", "-o"])
            .arg(&program)
            .args(own.iter().map(|unit| &unit.output))
            .args(whole.iter().map(|unit| &unit.output))
            .arg("--start-group")
            .arg(&archive)
            .args(&support)
            .arg(sysroot.join("lib/libc++.a"))
            .arg(builtins.trim())
            .arg("--end-group"),
    )?;
    Ok(program)
}

/// Runs each of [`RUNS`]; every one must reach its submissions.
fn run(program: &Path, directory: &Path) -> Result<()> {
    let mut failures = Vec::new();
    for gpus in RUNS {
        let mut command = Command::new("timeout");
        command
            .arg("120")
            .arg(program)
            .args(gpus)
            .stdin(Stdio::null())
            .env_remove("AMDGPU_GPU_ID")
            .env_remove("INTEL_STUB_GPU_DEVICE_ID");
        for gpu in gpus {
            match gpu.split_once(':') {
                Some(("amdgpu", device)) => command.env("AMDGPU_GPU_ID", device),
                Some((_, device)) => command.env("INTEL_STUB_GPU_DEVICE_ID", device),
                None => bail!("a run's GPU without its kernel driver: {gpu}"),
            };
        }
        let name = gpus.join("+").replace(':', "-");
        let output = command.output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(directory.join(format!("{name}.log")), &text)?;
        let reached = text
            .lines()
            .find(|line| line.starts_with("image device: ") && line.contains("submission"));
        match (output.status.success(), reached) {
            (true, Some(line)) => println!("{line}"),
            _ => failures.push(format!(
                "{}: {}",
                gpus.join(" "),
                text.lines()
                    .rev()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("no output")
            )),
        }
    }
    ensure!(
        failures.is_empty(),
        "the image's drivers failed on the host (logs in {}):\n{}",
        directory.display(),
        failures.join("\n")
    );
    println!(
        "the image's RADV and ANV, with its C library and defines, made their devices and \
         one submission on each GPU of {} runs",
        RUNS.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_target_and_coff_flags_change() {
        let words: Vec<String> = [
            IMAGE_TARGET,
            "-mno-stack-arg-probe",
            "-DHAVE_DL_ITERATE_PHDR",
            "-mno-incremental-linker-compatible",
            "-femulated-tls",
            "-c",
            "a.c",
        ]
        .map(str::to_owned)
        .to_vec();
        assert_eq!(
            retargeted(&words),
            [
                LINUX_TARGET,
                "-DHAVE_DL_ITERATE_PHDR",
                "-femulated-tls",
                "-c",
                "a.c"
            ]
        );
    }
}
