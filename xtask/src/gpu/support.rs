//! Source locations and build evidence shared by the native GPU tasks.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

/// The C target of the native GPU code, as `stela-driver-gpu/build/native.rs`
/// compiles it: LP64 COFF with the UEFI Win64 calling convention.
pub const NATIVE_TARGET: &str = "x86_64-pc-cygwin";

/// Stela's GPU sources.
pub fn gpu() -> PathBuf {
    crate::tools::root().join("crates/stela-driver-gpu/src")
}

/// An upstream source: the submodule `third_party/<name>`.
pub fn third_party(name: &str) -> PathBuf {
    crate::tools::root().join("third_party").join(name)
}

/// A path as Meson's files and `.pc` files read it: a backslash is an escape in both.
pub fn slashed(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

/// Archives `members` into `archive`, which takes the new archive only when
/// its bytes differ ([`replace_if_changed`]): an unchanged archive keeps its
/// modification time, and so the Cargo builds that watch it stay fresh.
/// Whether it changed.
pub fn archive<'a>(
    archiver: &Path,
    archive: &Path,
    members: impl Iterator<Item = &'a PathBuf>,
) -> Result<bool> {
    let fresh = fresh(archive);
    make_archive(archiver, &fresh, members)?;
    replace_if_changed(&fresh, archive)
}

/// Archives `members` into a new `output`, through a response file:
/// thousands of paths outgrow a Windows command line.
pub fn make_archive<'a>(
    archiver: &Path,
    output: &Path,
    members: impl Iterator<Item = &'a PathBuf>,
) -> Result<()> {
    if output.is_file() {
        fs::remove_file(output)?;
    }
    let list = output.with_extension("rsp");
    let quoted: Vec<_> = members
        .map(|member| format!("\"{}\"", slashed(member)))
        .collect();
    fs::write(&list, quoted.join("\n"))?;
    crate::tools::exec(
        Command::new(archiver)
            .arg("rcs")
            .arg(output)
            .arg(format!("@{}", list.display())),
    )
}

/// Where a new copy of `path` is made before it replaces `path`: beside it,
/// with `.new` added to its name.
pub fn fresh(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".new");
    path.with_file_name(name)
}

/// Moves `fresh` over `target` when their bytes differ, and otherwise
/// removes it, so a file made again with the same content keeps its
/// modification time. Whether `target` changed.
pub fn replace_if_changed(fresh: &Path, target: &Path) -> Result<bool> {
    if same_bytes(fresh, target)? {
        fs::remove_file(fresh)?;
        return Ok(false);
    }
    fs::rename(fresh, target)
        .with_context(|| format!("cannot move {} to {}", fresh.display(), target.display()))?;
    Ok(true)
}

/// The new copy (`new`) or the kept copy (`kept`) of `target`, a file under
/// `root`, in `directory`: outside the directories Cargo's builds watch, as a
/// file made or removed in one of those changes its time, which Cargo takes
/// for a change of what it holds. The name is `target`'s path under `root`.
pub fn copy_in(directory: &Path, root: &Path, target: &Path, kind: &str) -> PathBuf {
    let relative = target.strip_prefix(root).unwrap_or(target);
    let name = relative.to_string_lossy().replace(['/', '\\'], "__");
    directory.join(format!("{name}.{kind}"))
}

/// Puts `fresh` at `target`, a file another generator may have rewritten
/// since this was last done, as Ninja rewrites Meson's bindgen outputs:
/// `kept` holds the content last put there, with its modification time.
/// When `fresh` holds the same bytes, `target` takes them back with that
/// time, so to Cargo, which compares times, it is unchanged; otherwise
/// `fresh` becomes both. Whether the content changed.
pub fn restore_if_unchanged(fresh: &Path, target: &Path, kept: &Path) -> Result<bool> {
    let changed = !same_bytes(fresh, kept)?;
    if changed {
        fs::rename(fresh, kept)?;
    } else {
        fs::remove_file(fresh)?;
    }
    if !same_bytes(kept, target)? {
        fs::copy(kept, target)?;
    }
    let time = fs::metadata(kept)?.modified()?;
    File::options()
        .write(true)
        .open(target)?
        .set_modified(time)?;
    Ok(changed)
}

/// Writes `bytes` to `path` unless it holds them already, keeping its
/// modification time then. Whether it wrote.
pub fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool> {
    if fs::read(path).is_ok_and(|current| current == bytes) {
        return Ok(false);
    }
    fs::write(path, bytes)?;
    Ok(true)
}

/// Whether the files `first` and `second` both exist and hold the same
/// bytes, read a part at a time: an archive can be hundreds of megabytes.
pub fn same_bytes(first: &Path, second: &Path) -> Result<bool> {
    let (Ok(one), Ok(other)) = (fs::metadata(first), fs::metadata(second)) else {
        return Ok(false);
    };
    if one.len() != other.len() {
        return Ok(false);
    }
    let (mut one, mut other) = (File::open(first)?, File::open(second)?);
    let (mut left, mut right) = (vec![0; 1 << 20], vec![0; 1 << 20]);
    loop {
        let read = one.read(&mut left)?;
        if read == 0 {
            return Ok(true);
        }
        other.read_exact(&mut right[..read])?;
        if left[..read] != right[..read] {
            return Ok(false);
        }
    }
}

/// Where the GPU build trees are.
pub fn build_root() -> PathBuf {
    crate::tools::root().join("target/gpu")
}

/// A build tree under Cargo's target directory.
pub fn build_directory(name: &str) -> PathBuf {
    build_root().join(name)
}

pub fn capture(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("cannot execute {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("tool output is not UTF-8")
}

/// A tool from Stela's local GPU tool environment, or else from PATH.
pub fn tool(name: &str, local: &str) -> Result<PathBuf> {
    let path = crate::tools::root()
        .join(".tools/gpu")
        .join(local)
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    path.is_file()
        .then_some(path)
        .or_else(|| crate::tools::which(name))
        .with_context(|| format!("install {name} and put it in PATH"))
}

pub fn evidence_directory() -> Result<PathBuf> {
    let run = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let parent = crate::tools::root().join(".stela/gpu/evidence");
    fs::create_dir_all(&parent)?;
    let path = parent.join(run.to_string());
    fs::create_dir(&path)?;
    Ok(path)
}

/// Bind a source tree as checked out, with Stela's patches, local edits and
/// downloaded build dependencies. A link is bound by its target, as Git
/// records it. Repository metadata, ignored caches and generated Python
/// bytecode are not source inputs.
pub fn source_binding(root: &Path) -> Result<String> {
    fn collect(root: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if [".git", "__pycache__", "packagecache", ".wraplock"]
                .iter()
                .any(|n| name == *n)
            {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                collect(&entry.path(), paths)?;
            } else if kind.is_file() || kind.is_symlink() {
                paths.push(entry.path());
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    collect(root, &mut paths)?;
    paths.sort();
    let mut digest = Sha256::new();
    for path in paths {
        let name = path.strip_prefix(root)?.to_string_lossy();
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        let mut file_hash = Sha256::new();
        if fs::symlink_metadata(&path)?.is_symlink() {
            file_hash.update(b"link\0");
            file_hash.update(fs::read_link(&path)?.as_os_str().as_encoded_bytes());
        } else {
            let mut input = File::open(path)?;
            let mut buffer = [0; 64 * 1024];
            loop {
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                file_hash.update(&buffer[..n]);
            }
        }
        digest.update(file_hash.finalize());
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn time(path: &Path) -> SystemTime {
        fs::metadata(path).unwrap().modified().unwrap()
    }

    /// An hour before the test, the same instant for every file.
    fn hour_ago() -> SystemTime {
        static START: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();
        *START.get_or_init(|| SystemTime::now() - Duration::from_secs(3600))
    }

    fn age(path: &Path) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(hour_ago())
            .unwrap();
    }

    #[test]
    fn a_file_made_again_alike_keeps_its_time_and_a_different_one_replaces_it() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("libdemo.a");
        fs::write(&target, b"same").unwrap();
        age(&target);
        let before = time(&target);
        let fresh = fresh(&target);
        assert_eq!(fresh.file_name().unwrap(), "libdemo.a.new");
        fs::write(&fresh, b"same").unwrap();
        assert!(!replace_if_changed(&fresh, &target).unwrap());
        assert!(!fresh.exists());
        assert_eq!(time(&target), before);
        fs::write(&fresh, b"other").unwrap();
        assert!(replace_if_changed(&fresh, &target).unwrap());
        assert_eq!(fs::read(&target).unwrap(), b"other");
        assert!(!fresh.exists());
        assert!(!write_if_changed(&target, b"other").unwrap());
        assert!(write_if_changed(&target, b"third").unwrap());
        assert!(!same_bytes(&target, &directory.path().join("missing")).unwrap());
    }

    #[test]
    fn bindings_a_generator_rewrote_come_back_with_the_time_they_last_changed() {
        let directory = tempfile::tempdir().unwrap();
        let build = directory.path().join("build");
        let copies = directory.path().join("bindings");
        fs::create_dir_all(build.join("src")).unwrap();
        fs::create_dir_all(&copies).unwrap();
        let target = build.join("src/bindings.rs");
        let (fresh, kept) = (
            copy_in(&copies, &build, &target, "new"),
            copy_in(&copies, &build, &target, "kept"),
        );
        assert_eq!(kept, copies.join("src__bindings.rs.kept"));
        let put = |bytes: &[u8]| {
            fs::write(&fresh, bytes).unwrap();
            restore_if_unchanged(&fresh, &target, &kept).unwrap()
        };
        // The first bindings are new; then the generator rewrites the file.
        assert!(put(b"ours"));
        age(&target);
        age(&kept);
        let changed_at = time(&target);
        fs::write(&target, b"meson's").unwrap();
        // The same bindings again: ours are back, with their old time.
        let watched = time(&build.join("src"));
        assert!(!put(b"ours"));
        assert_eq!(fs::read(&target).unwrap(), b"ours");
        assert_eq!(time(&target), changed_at);
        // Nothing was made or removed beside it: its directory's time stays.
        assert_eq!(time(&build.join("src")), watched);
        // New bindings take the file and a new time.
        assert!(put(b"new"));
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(time(&target) > changed_at);
    }
}
