pub mod identity;
pub mod trust_db;

/// Writes `bytes` to `path` as a private file.
///
/// The identity seed and the pinned fingerprints must not be readable by other
/// local users. `OpenOptions::mode` only applies when the file is created, so a
/// file left behind with wider permissions would stay readable; the explicit
/// `set_permissions` below clamps it on every write.
pub fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // Best effort: a filesystem that cannot represent the mode must not
        // stop us from persisting the identity.
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        std::io::Write::write_all(&mut file, bytes)
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_private_file_clamps_permissions_of_an_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "hopchat_perm_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        // An existing world-readable file must be tightened, not trusted.
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private_file(&path, b"secret").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key material must end up 0600, got {:o}", mode);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");

        let _ = std::fs::remove_file(&path);
    }
}
