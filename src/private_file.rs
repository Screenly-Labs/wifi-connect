//! Writing files that hold the setup AP's passphrase.
//!
//! `--qr-output` writes the join QR as an SVG and as the raw `WIFI:`
//! payload. Both carry the passphrase — the `.txt` in plain text — and the
//! passphrase is what gets you onto the setup network and therefore to the
//! portal. So those files are written the way a credential is:
//!
//! * **Not world-readable.** Directory `0750`, files `0640`, set at
//!   creation time rather than inherited from whatever umask the service
//!   happens to run under (typically `022`, which gives `0644`). The mode
//!   is an upper bound: a stricter umask still wins.
//! * **Never through a symlink.** `std::fs::write` opens with `O_CREAT`
//!   and follows a symlink already sitting at the target, so anyone who can
//!   plant one there redirects the credential into a file of their
//!   choosing. Instead we write a sibling temp file opened with
//!   `O_CREAT|O_EXCL` (which refuses to follow a symlink) and `rename(2)` it
//!   over the target; rename replaces a symlink rather than writing through
//!   it.
//! * **Atomically.** A host application polling the file sees either the
//!   old payload or the new one, never a half-written one.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Mode for a directory we create to hold credential files.
pub const DIR_MODE: u32 = 0o750;

/// Mode for a credential file.
pub const FILE_MODE: u32 = 0o640;

/// Create `dir` (and any missing parents) with [`DIR_MODE`].
///
/// A directory that already exists is left alone: it is the operator's —
/// a container volume mount point, a path shared with the host
/// application — and its permissions are theirs to choose. The files
/// inside are protected by [`FILE_MODE`] either way.
pub fn create_dir(dir: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(DIR_MODE).create(dir)
}

/// Atomically replace `path` with `contents`, mode [`FILE_MODE`], without
/// following a symlink at `path`.
pub fn write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let tmp = temp_path(path)?;

    // A temp file left behind by a crash would make O_EXCL fail forever,
    // so clear it first. remove_file unlinks a symlink rather than its
    // target, and if something re-plants one in the window before the open
    // below, O_EXCL refuses it and we fail closed.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();

    if result.is_err() {
        // Best effort: do not leave a stray copy of the credential behind.
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// `dir/.name.tmp` — in the same directory, so the rename cannot cross a
/// filesystem boundary and is atomic.
fn temp_path(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".tmp");
    Ok(path.with_file_name(tmp_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// A scratch directory unique to one test, removed on drop. Hand-rolled
    /// rather than pulling in a crate for four tests.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "wifi-connect-private-file-{}-{test}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The mode is an upper bound (the umask can only remove bits), so
    /// assert there is nothing beyond it — in particular nothing for
    /// "other".
    #[test]
    fn written_files_are_not_world_readable() {
        let s = Scratch::new("file-mode");
        let f = s.0.join("wifi-connect-qr.txt");
        write(&f, b"WIFI:S:x;T:WPA;P:secret;;").unwrap();

        assert_eq!(fs::read(&f).unwrap(), b"WIFI:S:x;T:WPA;P:secret;;");
        let m = mode(&f);
        assert_eq!(m & !FILE_MODE, 0, "file mode {m:o} exceeds {FILE_MODE:o}");
        assert_eq!(m & 0o007, 0, "file is accessible to other: {m:o}");
    }

    #[test]
    fn a_created_directory_is_not_world_readable() {
        let s = Scratch::new("dir-mode");
        let d = s.0.join("nested").join("qr");
        create_dir(&d).unwrap();

        let m = mode(&d);
        assert_eq!(m & !DIR_MODE, 0, "dir mode {m:o} exceeds {DIR_MODE:o}");
        assert_eq!(m & 0o007, 0, "dir is accessible to other: {m:o}");

        // Existing directories are accepted, not an error.
        create_dir(&d).unwrap();
    }

    /// Earlier versions wrote these files `0644`. Overwriting in place
    /// would keep that mode; replacing the file must not.
    #[test]
    fn replacing_a_world_readable_file_does_not_keep_its_mode() {
        let s = Scratch::new("replace-mode");
        let f = s.0.join("wifi-connect-qr.svg");
        fs::write(&f, b"old").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();

        write(&f, b"new").unwrap();

        assert_eq!(fs::read(&f).unwrap(), b"new");
        assert_eq!(mode(&f) & 0o007, 0, "kept the old world-readable mode");
    }

    /// The attack `std::fs::write` was open to: plant a symlink where the
    /// QR payload is about to be written, and the passphrase lands in a
    /// file of the attacker's choosing.
    #[test]
    fn a_symlink_at_the_target_is_replaced_not_followed() {
        let s = Scratch::new("symlink-target");
        let elsewhere = s.0.join("attacker-readable");
        fs::write(&elsewhere, b"untouched").unwrap();
        let f = s.0.join("wifi-connect-qr.txt");
        symlink(&elsewhere, &f).unwrap();

        write(&f, b"secret").unwrap();

        assert_eq!(fs::read(&elsewhere).unwrap(), b"untouched");
        assert!(
            !fs::symlink_metadata(&f).unwrap().file_type().is_symlink(),
            "the target is still a symlink"
        );
        assert_eq!(fs::read(&f).unwrap(), b"secret");
    }

    /// Same attack aimed at the temp file instead of the target.
    #[test]
    fn a_symlink_at_the_temp_path_is_not_followed() {
        let s = Scratch::new("symlink-temp");
        let elsewhere = s.0.join("attacker-readable");
        fs::write(&elsewhere, b"untouched").unwrap();
        let f = s.0.join("wifi-connect-qr.txt");
        symlink(&elsewhere, temp_path(&f).unwrap()).unwrap();

        write(&f, b"secret").unwrap();

        assert_eq!(fs::read(&elsewhere).unwrap(), b"untouched");
        assert_eq!(fs::read(&f).unwrap(), b"secret");
        assert!(
            fs::symlink_metadata(temp_path(&f).unwrap()).is_err(),
            "the temp file was left behind"
        );
    }
}
