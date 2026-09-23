//! Linux-first ciphertext persistence. Directory-relative operations avoid path
//! replacement races; the adjacent lock inode survives every vault replacement.
use anyhow::Error;
use std::fmt;

#[derive(Debug)]
pub struct SaveError {
    source: Error,
    committed: bool,
}

impl SaveError {
    /// True means publication occurred but durability is uncertain. Stop writes
    /// and reopen; do not represent the previous in-memory state as current.
    pub fn committed(&self) -> bool {
        self.committed
    }

    fn new(source: Error, committed: bool) -> Self {
        Self { source, committed }
    }
}

impl fmt::Display for SaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.committed {
            write!(
                f,
                "Vault was published, but durability is uncertain; reopen before writing: {:#}",
                self.source
            )
        } else {
            write!(f, "Vault was not saved: {:#}", self.source)
        }
    }
}

impl std::error::Error for SaveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(target_os = "linux")]
pub use linux::VaultFile;

#[cfg(target_os = "linux")]
mod linux {
    use super::SaveError;
    use crate::crypto::MAX_FILE_SIZE;
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use fs2::FileExt;
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};

    pub struct VaultFile {
        path: PathBuf,
        directory: File,
        name: CString,
        lock_name: CString,
        lock: File,
        uncertain: bool,
        #[cfg(test)]
        fault: Option<Stage>,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Stage {
        TempCreate,
        Write,
        FileSync,
        Publish,
        DirectorySync,
    }

    impl VaultFile {
        pub fn open(path: PathBuf) -> Result<Self> {
            let path = if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            };
            let filename = path
                .file_name()
                .ok_or_else(|| anyhow!("Vault path must name a file."))?;
            let name = cstring(filename)?;
            let mut lock_bytes = filename.as_bytes().to_vec();
            lock_bytes.extend_from_slice(b".lock");
            let lock_name = CString::new(lock_bytes).context("Invalid lock filename.")?;
            let parent = path
                .parent()
                .ok_or_else(|| anyhow!("Vault path has no parent directory."))?;
            let directory = open_or_create_directory(parent)?;
            let lock = open_at(
                directory.as_raw_fd(),
                &lock_name,
                libc::O_RDWR | libc::O_CREAT,
                0o600,
            )
            .context("Cannot open vault lock (symlinks and special files are refused).")?;
            validate_private_file(&lock, "lock")?;
            FileExt::try_lock_exclusive(&lock).context(
                "Cannot acquire vault lock; another SimpleCrypt process may be using this vault.",
            )?;
            let result = Self {
                path,
                directory,
                name,
                lock_name,
                lock,
                uncertain: false,
                #[cfg(test)]
                fault: None,
            };
            result.check_lock()?;
            // The vault is not inspected until after acquiring the stable lock.
            result.exists()?;
            Ok(result)
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn exists(&self) -> Result<bool> {
            self.check_lock()?;
            Ok(self.open_vault()?.is_some())
        }

        pub fn read(&self) -> Result<Vec<u8>> {
            self.check_lock()?;
            let file = self
                .open_vault()?
                .ok_or_else(|| anyhow!("Vault does not exist."))?;
            ensure!(
                file.metadata()?.len() <= MAX_FILE_SIZE as u64,
                "Vault exceeds the file size limit."
            );
            let mut bytes = Vec::new();
            file.take(MAX_FILE_SIZE as u64 + 1)
                .read_to_end(&mut bytes)
                .context("Cannot read encrypted vault.")?;
            ensure!(
                bytes.len() <= MAX_FILE_SIZE,
                "Vault exceeds the file size limit."
            );
            Ok(bytes)
        }

        /// The caller must pass an encrypted envelope, never serialized plaintext.
        /// `create` publishes without clobbering; replacement requires an existing
        /// validated vault. No failure before publication changes the old vault.
        pub fn save(&mut self, bytes: &[u8], create: bool) -> std::result::Result<(), SaveError> {
            if self.uncertain {
                return Err(SaveError::new(
                    anyhow!("A previous save requires reopening the vault."),
                    true,
                ));
            }
            let before_publish = (|| -> Result<()> {
                ensure!(
                    !bytes.is_empty() && bytes.len() <= MAX_FILE_SIZE,
                    "Invalid encrypted vault size."
                );
                self.check_lock()?;
                let existing = self.open_vault()?;
                ensure!(
                    create || existing.is_some(),
                    "Cannot replace a missing vault; reopen to initialize it."
                );
                ensure!(
                    !create || existing.is_none(),
                    "A vault already exists; creation will not overwrite it."
                );
                self.checkpoint(Stage::TempCreate)?;
                let mut temporary = TempCiphertext::create(self.directory.as_raw_fd())?;
                self.checkpoint(Stage::Write)?;
                temporary
                    .file
                    .write_all(bytes)
                    .context("Cannot write encrypted temporary vault.")?;
                self.checkpoint(Stage::FileSync)?;
                temporary
                    .file
                    .sync_all()
                    .context("Cannot sync encrypted temporary vault.")?;
                // Recheck lock and target just before publishing. Rename never
                // follows a destination symlink, even if a path is substituted.
                self.check_lock()?;
                let current = self.open_vault()?;
                ensure!(
                    create || current.is_some(),
                    "Vault disappeared before replacement."
                );
                if let (Some(before), Some(now)) = (&existing, &current) {
                    let before = before.metadata()?;
                    let now = now.metadata()?;
                    ensure!(
                        before.dev() == now.dev() && before.ino() == now.ino(),
                        "Vault changed outside the locked session."
                    );
                }
                self.checkpoint(Stage::Publish)?;
                temporary
                    .publish(&self.name, create)
                    .context("Cannot publish encrypted vault.")?;
                Ok(())
            })();
            before_publish.map_err(|error| SaveError::new(error, false))?;
            let after_publish = self.checkpoint(Stage::DirectorySync).and_then(|()| {
                self.directory
                    .sync_all()
                    .context("Cannot sync vault directory.")
            });
            if let Err(error) = after_publish {
                self.uncertain = true;
                return Err(SaveError::new(error, true));
            }
            Ok(())
        }

        fn checkpoint(&self, _stage: Stage) -> Result<()> {
            #[cfg(test)]
            if self.fault == Some(_stage) {
                bail!("Injected persistence failure.");
            }
            Ok(())
        }

        fn open_vault(&self) -> Result<Option<File>> {
            match open_at(self.directory.as_raw_fd(), &self.name, libc::O_RDONLY, 0) {
                Ok(file) => {
                    validate_private_file(&file, "vault")?;
                    Ok(Some(file))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error)
                    .context("Cannot open vault (symlinks and special files are refused)."),
            }
        }

        fn check_lock(&self) -> Result<()> {
            let current = open_at(
                self.directory.as_raw_fd(),
                &self.lock_name,
                libc::O_RDONLY,
                0,
            )
            .context("Vault lock path changed; close and reopen the vault.")?;
            validate_private_file(&current, "lock")?;
            let held = self.lock.metadata()?;
            let current = current.metadata()?;
            ensure!(
                held.dev() == current.dev() && held.ino() == current.ino(),
                "Vault lock was replaced; close and reopen the vault."
            );
            Ok(())
        }
    }

    fn cstring(name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes()).context("File path contains a NUL byte.")
    }

    fn open_at(
        directory: RawFd,
        name: &CString,
        flags: i32,
        mode: libc::mode_t,
    ) -> io::Result<File> {
        // SAFETY: name is NUL-terminated; the returned descriptor is newly owned.
        let fd = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                mode,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a unique valid descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn validate_private_file(file: &File, role: &str) -> Result<()> {
        let metadata = file
            .metadata()
            .context("Cannot inspect vault file metadata.")?;
        ensure!(metadata.is_file(), "The {role} must be a regular file.");
        // SAFETY: geteuid has no preconditions.
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "The {role} must be owned by the current user."
        );
        ensure!(
            metadata.mode() & 0o7777 == 0o600,
            "The {role} must have private permissions (0600)."
        );
        ensure!(
            metadata.nlink() == 1,
            "The {role} must not have additional hard links."
        );
        Ok(())
    }

    fn open_or_create_directory(path: &Path) -> Result<File> {
        let root = CString::new("/").expect("static path");
        let mut current = open_at(libc::AT_FDCWD, &root, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .context("Cannot open filesystem root.")?;
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => cstring(name)?,
                Component::ParentDir => CString::new("..").expect("static path"),
                Component::Prefix(_) => bail!("Unsupported vault path."),
            };
            current = match open_at(
                current.as_raw_fd(),
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            ) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // SAFETY: current is live and name is a NUL-terminated component.
                    let status =
                        unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
                    if status != 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(error).context("Cannot create private vault directory.");
                        }
                    }
                    let created = open_at(
                        current.as_raw_fd(),
                        &name,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                        0,
                    )
                    .context("Cannot open newly created vault directory.")?;
                    // Persist each directory entry as well as the eventual vault.
                    current
                        .sync_all()
                        .context("Cannot sync parent of new vault directory.")?;
                    created
                }
                Err(error) => {
                    return Err(error)
                        .context("Cannot open vault directory (symlink components are refused).");
                }
            };
        }
        Ok(current)
    }

    struct TempCiphertext {
        file: File,
        directory: RawFd,
        name: CString,
        published: bool,
    }

    impl TempCiphertext {
        fn create(directory: RawFd) -> Result<Self> {
            for _ in 0..32 {
                let mut random = [0_u8; 16];
                getrandom::getrandom(&mut random)
                    .map_err(|_| anyhow!("Operating-system randomness is unavailable."))?;
                let name = format!(".simplecrypt-{:032x}.tmp", u128::from_le_bytes(random));
                let name = CString::new(name).expect("generated ASCII filename");
                match open_at(
                    directory,
                    &name,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                ) {
                    Ok(file) => {
                        let temporary = Self {
                            file,
                            directory,
                            name,
                            published: false,
                        };
                        validate_private_file(&temporary.file, "temporary vault")?;
                        return Ok(temporary);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error)
                            .context("Cannot create private encrypted temporary vault.");
                    }
                }
            }
            bail!("Cannot allocate a unique encrypted temporary vault.")
        }

        fn publish(&mut self, destination: &CString, create: bool) -> io::Result<()> {
            // SAFETY: descriptors and NUL-terminated names remain valid. Linux
            // renameat2 gives atomic no-clobber creation without hard-link gaps.
            let status = unsafe {
                libc::renameat2(
                    self.directory,
                    self.name.as_ptr(),
                    self.directory,
                    destination.as_ptr(),
                    if create { libc::RENAME_NOREPLACE } else { 0 },
                )
            };
            if status != 0 {
                return Err(io::Error::last_os_error());
            }
            self.published = true;
            Ok(())
        }
    }

    impl Drop for TempCiphertext {
        fn drop(&mut self) {
            if !self.published {
                // SAFETY: this private guard never outlives VaultFile's directory.
                // Best-effort cleanup only; any leftover bytes are ciphertext.
                unsafe {
                    libc::unlinkat(self.directory, self.name.as_ptr(), 0);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::Session;
        use crate::model::Template;
        use std::fs::{self, OpenOptions};
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
        use tempfile::TempDir;

        fn setup() -> (TempDir, PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.scv");
            (dir, path)
        }

        fn private_file(path: &Path, bytes: &[u8]) {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(bytes).unwrap();
        }

        fn temp_count(dir: &Path) -> usize {
            fs::read_dir(dir)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().as_bytes().starts_with(b".simplecrypt-"))
                .count()
        }

        #[test]
        fn creation_replacement_restart_and_permissions() {
            let (dir, path) = setup();
            let mut vault = VaultFile::open(path.clone()).unwrap();
            assert!(!vault.exists().unwrap());
            assert!(vault.read().is_err());
            assert!(
                !vault
                    .save(b"encrypted-before", false)
                    .unwrap_err()
                    .committed()
            );
            vault.save(b"encrypted-before", true).unwrap();
            let first_inode = fs::metadata(&path).unwrap().ino();
            let lock_inode = fs::metadata(path.with_extension("scv.lock")).unwrap().ino();
            assert!(vault.save(b"must-not-clobber", true).is_err());
            assert_eq!(vault.read().unwrap(), b"encrypted-before");
            vault.save(b"encrypted-after", false).unwrap();
            assert_ne!(first_inode, fs::metadata(&path).unwrap().ino());
            assert_eq!(
                lock_inode,
                fs::metadata(path.with_extension("scv.lock")).unwrap().ino()
            );
            for entry in fs::read_dir(dir.path()).unwrap() {
                assert_eq!(entry.unwrap().metadata().unwrap().mode() & 0o777, 0o600);
            }
            assert_eq!(temp_count(dir.path()), 0);
            drop(vault);
            let reopened = VaultFile::open(path.clone()).unwrap();
            assert_eq!(reopened.path(), path);
            assert_eq!(reopened.read().unwrap(), b"encrypted-after");
        }

        #[test]
        fn missing_directories_are_private_existing_parents_unchanged() {
            let (dir, _) = setup();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let path = dir.path().join("new/nested/vault");
            let mut vault = VaultFile::open(path).unwrap();
            vault.save(b"encrypted", true).unwrap();
            assert_eq!(fs::metadata(dir.path()).unwrap().mode() & 0o777, 0o755);
            for path in [dir.path().join("new"), dir.path().join("new/nested")] {
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o700);
            }
        }

        #[test]
        fn stable_lock_contends_even_after_rename() {
            let (_dir, path) = setup();
            let mut first = VaultFile::open(path.clone()).unwrap();
            assert!(VaultFile::open(path.clone()).is_err());
            first.save(b"encrypted", true).unwrap();
            first.save(b"replacement", false).unwrap();
            assert!(VaultFile::open(path.clone()).is_err());
            drop(first);
            assert!(VaultFile::open(path).is_ok());
        }

        #[test]
        fn process_lock_child() {
            let Some(path) = std::env::var_os("SIMPLECRYPT_TEST_LOCK_PATH") else {
                return;
            };
            let error = VaultFile::open(PathBuf::from(path))
                .err()
                .expect("child must not acquire held lock");
            assert!(error.to_string().contains("Cannot acquire vault lock"));
        }

        #[test]
        fn separate_process_cannot_acquire_lock_across_publication() {
            let (_dir, path) = setup();
            let mut vault = VaultFile::open(path.clone()).unwrap();
            for create in [true, false] {
                vault.save(b"encrypted", create).unwrap();
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "storage::linux::tests::process_lock_child",
                        "--nocapture",
                    ])
                    .env("SIMPLECRYPT_TEST_LOCK_PATH", &path)
                    .status()
                    .unwrap();
                assert!(status.success());
            }
        }

        #[test]
        fn lock_replacement_is_detected() {
            let (_dir, path) = setup();
            let mut first = VaultFile::open(path.clone()).unwrap();
            let lock_path = path.with_extension("scv.lock");
            fs::remove_file(&lock_path).unwrap();
            private_file(&lock_path, b"");
            assert!(first.exists().is_err());
            assert!(first.save(b"encrypted", true).is_err());
            assert!(!path.exists());
        }

        #[test]
        fn refuses_symlinks_special_files_hardlinks_and_unsafe_modes() {
            let (dir, path) = setup();
            let target = dir.path().join("target");
            private_file(&target, b"original");
            symlink(&target, &path).unwrap();
            assert!(VaultFile::open(path.clone()).is_err());
            assert_eq!(fs::read(&target).unwrap(), b"original");
            fs::remove_file(&path).unwrap();
            fs::hard_link(&target, &path).unwrap();
            assert!(VaultFile::open(path.clone()).is_err());
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            assert!(VaultFile::open(path.clone()).is_err());
            fs::remove_dir(&path).unwrap();
            let fifo_name = cstring(path.as_os_str()).unwrap();
            // SAFETY: fifo_name is a valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
            assert!(VaultFile::open(path.clone()).is_err()); // O_NONBLOCK prevents hangs.
            fs::remove_file(&path).unwrap();
            private_file(&path, b"existing");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(VaultFile::open(path.clone()).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let lock = path.with_extension("scv.lock");
            fs::remove_file(&lock).unwrap();
            symlink(&target, &lock).unwrap();
            assert!(VaultFile::open(path.clone()).is_err());
            fs::remove_file(&lock).unwrap();
            private_file(&lock, b"");
            fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(VaultFile::open(path).is_err());
        }

        #[test]
        fn refuses_parent_symlinks_and_changed_vault_paths() {
            let (dir, path) = setup();
            let link = dir.path().join("link");
            symlink(dir.path(), &link).unwrap();
            assert!(VaultFile::open(link.join("other-vault")).is_err());
            let mut vault = VaultFile::open(path.clone()).unwrap();
            vault.save(b"original", true).unwrap();
            fs::remove_file(&path).unwrap();
            symlink(dir.path().join("does-not-exist"), &path).unwrap();
            assert!(vault.read().is_err());
            assert!(vault.save(b"replacement", false).is_err());
            assert!(!dir.path().join("does-not-exist").exists());
        }

        #[test]
        fn reads_are_bounded_and_empty_existing_vault_is_not_missing() {
            let (_dir, path) = setup();
            private_file(&path, b"");
            let mut vault = VaultFile::open(path.clone()).unwrap();
            assert!(vault.exists().unwrap());
            assert!(vault.read().unwrap().is_empty());
            assert!(vault.save(b"new", true).is_err());
            let file = OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len(MAX_FILE_SIZE as u64 + 1).unwrap();
            assert!(vault.read().is_err());
            assert!(vault.save(&[], false).is_err());
            assert!(vault.save(&vec![0; MAX_FILE_SIZE + 1], false).is_err());
        }

        #[test]
        fn no_clobber_publication_is_atomic_even_after_prior_check() {
            let (_dir, path) = setup();
            let vault = VaultFile::open(path.clone()).unwrap();
            let mut temp = TempCiphertext::create(vault.directory.as_raw_fd()).unwrap();
            temp.file.write_all(b"replacement").unwrap();
            private_file(&path, b"racing-creator");
            assert_eq!(
                temp.publish(&vault.name, true).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(fs::read(&path).unwrap(), b"racing-creator");
        }

        #[test]
        fn injected_precommit_failures_preserve_saved_bytes_and_clean_temps() {
            for stage in [
                Stage::TempCreate,
                Stage::Write,
                Stage::FileSync,
                Stage::Publish,
            ] {
                let (dir, path) = setup();
                let mut vault = VaultFile::open(path).unwrap();
                vault.save(b"previous-ciphertext", true).unwrap();
                vault.fault = Some(stage);
                let error = vault.save(b"next-ciphertext", false).unwrap_err();
                assert!(!error.committed());
                assert_eq!(vault.read().unwrap(), b"previous-ciphertext");
                assert_eq!(temp_count(dir.path()), 0);
                vault.fault = None;
                vault.save(b"retry-ciphertext", false).unwrap();
            }
        }

        #[test]
        fn postcommit_sync_failure_reports_uncertainty_and_blocks_writes() {
            for create in [true, false] {
                let (dir, path) = setup();
                let mut vault = VaultFile::open(path.clone()).unwrap();
                if !create {
                    vault.save(b"previous-ciphertext", true).unwrap();
                }
                vault.fault = Some(Stage::DirectorySync);
                let error = vault.save(b"published-ciphertext", create).unwrap_err();
                assert!(error.committed());
                assert!(error.to_string().contains("durability is uncertain"));
                assert_eq!(vault.read().unwrap(), b"published-ciphertext");
                assert_eq!(temp_count(dir.path()), 0);
                vault.fault = None;
                assert!(vault.save(b"blocked", false).unwrap_err().committed());
                drop(vault);
                let mut reopened = VaultFile::open(path).unwrap();
                reopened.save(b"after-reopen", false).unwrap();
            }
        }

        #[test]
        fn ciphertext_only_persistence_and_private_temporary_files() {
            let (dir, path) = setup();
            let mut session = Session::create("synthetic storage master").unwrap();
            let mut record = Template::Login.make_record().unwrap();
            record.label = "never-plaintext-label-93857".to_owned();
            record.fields[1].value = "never-plaintext-password-83649".to_owned();
            session.data.records.push(record);
            let encrypted = session.seal(&session.data).unwrap();
            let mut vault = VaultFile::open(path).unwrap();
            let mut temporary = TempCiphertext::create(vault.directory.as_raw_fd()).unwrap();
            temporary.file.write_all(&encrypted).unwrap();
            assert_eq!(temporary.file.metadata().unwrap().mode() & 0o777, 0o600);
            vault.save(&encrypted, true).unwrap();
            for entry in fs::read_dir(dir.path()).unwrap() {
                let bytes = fs::read(entry.unwrap().path()).unwrap();
                for sentinel in [
                    b"never-plaintext-label".as_slice(),
                    b"never-plaintext-password".as_slice(),
                ] {
                    assert!(
                        !bytes
                            .windows(sentinel.len())
                            .any(|window| window == sentinel)
                    );
                }
            }
            let restored =
                Session::unlock(&vault.read().unwrap(), "synthetic storage master").unwrap();
            assert!(restored.data.records[0].fields[1].value == "never-plaintext-password-83649");
        }
    }
}

// Keep unsupported platforms fail-closed rather than silently weakening storage.
#[cfg(not(target_os = "linux"))]
pub struct VaultFile;

#[cfg(not(target_os = "linux"))]
impl VaultFile {
    pub fn open(_: std::path::PathBuf) -> anyhow::Result<Self> {
        anyhow::bail!("Secure vault storage currently requires Linux.")
    }
    pub fn exists(&self) -> anyhow::Result<bool> {
        anyhow::bail!("Secure vault storage currently requires Linux.")
    }
    pub fn read(&self) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("Secure vault storage currently requires Linux.")
    }
    pub fn save(&mut self, _: &[u8], _: bool) -> Result<(), SaveError> {
        Err(SaveError::new(
            anyhow::anyhow!("Secure vault storage currently requires Linux."),
            false,
        ))
    }
    pub fn path(&self) -> &std::path::Path {
        std::path::Path::new("")
    }
}
