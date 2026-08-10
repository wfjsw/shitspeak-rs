//! Durable staging artifacts for strict foreign-lineage recovery.
//!
//! A staged repository image is not trusted merely because it was downloaded
//! successfully. The artifact binds the image to the recovery attempt, the
//! repository metadata, and the exact terminal cut that accompanied it. It is
//! fsynced before being returned so the terminal journal can safely reference
//! its path from a durable pending-install intent.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use aws_lc_rs::digest::{SHA256, digest};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    HistoryMetadata,
    terminal_journal::{DIGEST_LEN, JOURNAL_ID_LEN, TerminalCut},
};

const ARTIFACT_MAGIC: &[u8; 8] = b"SSRCVSTG";
const ARTIFACT_FORMAT_VERSION: u32 = 1;
const MANIFEST_LENGTH_BYTES: usize = 4;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;

/// The durable envelope to which a staged repository image must be bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryStagingExpectation {
    attempt_hi: u64,
    attempt_lo: u64,
    repository_metadata: HistoryMetadata,
    terminal_cut: TerminalCut,
}

impl RecoveryStagingExpectation {
    pub(crate) fn new(
        attempt_hi: u64,
        attempt_lo: u64,
        repository_metadata: HistoryMetadata,
        terminal_cut: TerminalCut,
    ) -> Self {
        Self {
            attempt_hi,
            attempt_lo,
            repository_metadata,
            terminal_cut,
        }
    }

    pub(crate) fn attempt_id(&self) -> (u64, u64) {
        (self.attempt_hi, self.attempt_lo)
    }

    pub(crate) fn repository_metadata(&self) -> HistoryMetadata {
        self.repository_metadata
    }

    pub(crate) fn terminal_cut(&self) -> TerminalCut {
        self.terminal_cut
    }
}

/// Verified metadata read from a recovery staging artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryStagingManifest {
    expectation: RecoveryStagingExpectation,
    content_len: u64,
    content_digest: [u8; DIGEST_LEN],
}

impl RecoveryStagingManifest {
    /// Rebuild a manifest descriptor from a durable pending-install intent.
    pub(crate) fn new(
        expectation: RecoveryStagingExpectation,
        content_len: u64,
        content_digest: [u8; DIGEST_LEN],
    ) -> Self {
        Self {
            expectation,
            content_len,
            content_digest,
        }
    }

    pub(crate) fn expectation(&self) -> RecoveryStagingExpectation {
        self.expectation
    }

    pub(crate) fn content_len(&self) -> u64 {
        self.content_len
    }

    pub(crate) fn content_digest(&self) -> &[u8; DIGEST_LEN] {
        &self.content_digest
    }
}

/// A repository image whose staging manifest and content digest are verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedRecoveryStagingArtifact {
    manifest: RecoveryStagingManifest,
    repository_image: Bytes,
}

impl VerifiedRecoveryStagingArtifact {
    pub(crate) fn manifest(&self) -> RecoveryStagingManifest {
        self.manifest
    }

    pub(crate) fn repository_image(&self) -> &Bytes {
        &self.repository_image
    }

    pub(crate) fn into_repository_image(self) -> Bytes {
        self.repository_image
    }
}

#[derive(Debug, Error)]
pub(crate) enum RecoveryStagingError {
    #[error("recovery staging I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("recovery staging manifest serialization failed: {0}")]
    ManifestSerialization(#[source] serde_json::Error),
    #[error("recovery staging artifact has an invalid header")]
    InvalidHeader,
    #[error("unsupported recovery staging artifact version {0}")]
    UnsupportedVersion(u32),
    #[error("recovery staging manifest length {0} is invalid")]
    InvalidManifestLength(usize),
    #[error("recovery staging manifest is invalid: {0}")]
    InvalidManifest(#[source] serde_json::Error),
    #[error("recovery staging artifact does not match the expected recovery envelope")]
    EnvelopeMismatch,
    #[error("recovery staging content length mismatch: manifest={expected}, actual={actual}")]
    ContentLengthMismatch { expected: u64, actual: u64 },
    #[error("recovery staging content digest mismatch")]
    ContentDigestMismatch,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedManifest {
    format_version: u32,
    attempt_hi: u64,
    attempt_lo: u64,
    repository_version: u64,
    repository_freshness: i64,
    journal_id: [u8; JOURNAL_ID_LEN],
    terminal_generation: u64,
    terminal_chain_digest: [u8; DIGEST_LEN],
    terminal_set_digest: [u8; DIGEST_LEN],
    content_len: u64,
    content_digest: [u8; DIGEST_LEN],
}

impl SerializedManifest {
    fn new(expectation: RecoveryStagingExpectation, repository_image: &[u8]) -> Self {
        let terminal_cut = expectation.terminal_cut();
        Self {
            format_version: ARTIFACT_FORMAT_VERSION,
            attempt_hi: expectation.attempt_hi,
            attempt_lo: expectation.attempt_lo,
            repository_version: expectation.repository_metadata.version,
            repository_freshness: expectation.repository_metadata.freshness,
            journal_id: *terminal_cut.journal_id(),
            terminal_generation: terminal_cut.generation(),
            terminal_chain_digest: *terminal_cut.chain_digest(),
            terminal_set_digest: *terminal_cut.terminal_set_digest(),
            content_len: repository_image.len() as u64,
            content_digest: sha256(repository_image),
        }
    }

    fn expectation(&self) -> RecoveryStagingExpectation {
        RecoveryStagingExpectation::new(
            self.attempt_hi,
            self.attempt_lo,
            HistoryMetadata {
                version: self.repository_version,
                freshness: self.repository_freshness,
            },
            TerminalCut::new(
                self.journal_id,
                self.terminal_generation,
                self.terminal_chain_digest,
                self.terminal_set_digest,
            ),
        )
    }

    fn public_manifest(&self) -> RecoveryStagingManifest {
        RecoveryStagingManifest {
            expectation: self.expectation(),
            content_len: self.content_len,
            content_digest: self.content_digest,
        }
    }
}

/// Write and fsync a new repository staging artifact.
///
/// The target is created with `create_new`; an existing artifact is never
/// overwritten. A failed write is removed best-effort because no journal
/// intent can reference it before this function succeeds.
pub(crate) fn write_recovery_staging_artifact(
    path: &Path,
    expectation: RecoveryStagingExpectation,
    repository_image: &[u8],
) -> Result<RecoveryStagingManifest, RecoveryStagingError> {
    let manifest = SerializedManifest::new(expectation, repository_image);
    let encoded_manifest =
        serde_json::to_vec(&manifest).map_err(RecoveryStagingError::ManifestSerialization)?;
    if encoded_manifest.len() > MAX_MANIFEST_BYTES {
        return Err(RecoveryStagingError::InvalidManifestLength(
            encoded_manifest.len(),
        ));
    }

    let parent = artifact_parent(path)?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| io_error(path, source))?;
        file.write_all(ARTIFACT_MAGIC)
            .and_then(|()| file.write_all(&(encoded_manifest.len() as u32).to_be_bytes()))
            .and_then(|()| file.write_all(&encoded_manifest))
            .and_then(|()| file.write_all(repository_image))
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error(path, source))?;
        sync_parent_directory(parent).map_err(|source| io_error(parent, source))
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(path);
    }
    write_result?;
    Ok(manifest.public_manifest())
}

/// Load an artifact only after its envelope, length, and SHA-256 are verified.
pub(crate) fn verify_recovery_staging_artifact(
    path: &Path,
    expected: RecoveryStagingManifest,
) -> Result<VerifiedRecoveryStagingArtifact, RecoveryStagingError> {
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let file_len = file
        .metadata()
        .map_err(|source| io_error(path, source))?
        .len();

    let mut magic = [0_u8; ARTIFACT_MAGIC.len()];
    file.read_exact(&mut magic)
        .map_err(|source| io_error(path, source))?;
    if &magic != ARTIFACT_MAGIC {
        return Err(RecoveryStagingError::InvalidHeader);
    }

    let mut encoded_manifest_len = [0_u8; MANIFEST_LENGTH_BYTES];
    file.read_exact(&mut encoded_manifest_len)
        .map_err(|source| io_error(path, source))?;
    let manifest_len = u32::from_be_bytes(encoded_manifest_len) as usize;
    if manifest_len == 0 || manifest_len > MAX_MANIFEST_BYTES {
        return Err(RecoveryStagingError::InvalidManifestLength(manifest_len));
    }

    let header_len = (ARTIFACT_MAGIC.len() + MANIFEST_LENGTH_BYTES) as u64;
    let actual_content_len = file_len
        .checked_sub(header_len + manifest_len as u64)
        .ok_or(RecoveryStagingError::InvalidManifestLength(manifest_len))?;
    let mut encoded_manifest = vec![0_u8; manifest_len];
    file.read_exact(&mut encoded_manifest)
        .map_err(|source| io_error(path, source))?;
    let manifest: SerializedManifest =
        serde_json::from_slice(&encoded_manifest).map_err(RecoveryStagingError::InvalidManifest)?;
    if manifest.format_version != ARTIFACT_FORMAT_VERSION {
        return Err(RecoveryStagingError::UnsupportedVersion(
            manifest.format_version,
        ));
    }
    let stored_manifest = manifest.public_manifest();
    if stored_manifest.expectation() != expected.expectation() {
        return Err(RecoveryStagingError::EnvelopeMismatch);
    }
    if stored_manifest.content_len() != expected.content_len() {
        return Err(RecoveryStagingError::ContentLengthMismatch {
            expected: expected.content_len(),
            actual: stored_manifest.content_len(),
        });
    }
    if stored_manifest.content_digest() != expected.content_digest() {
        return Err(RecoveryStagingError::ContentDigestMismatch);
    }
    if manifest.content_len != actual_content_len {
        return Err(RecoveryStagingError::ContentLengthMismatch {
            expected: manifest.content_len,
            actual: actual_content_len,
        });
    }

    let content_len = usize::try_from(actual_content_len).map_err(|_| {
        RecoveryStagingError::ContentLengthMismatch {
            expected: manifest.content_len,
            actual: actual_content_len,
        }
    })?;
    let mut repository_image = vec![0_u8; content_len];
    file.read_exact(&mut repository_image)
        .map_err(|source| io_error(path, source))?;
    if sha256(&repository_image) != manifest.content_digest {
        return Err(RecoveryStagingError::ContentDigestMismatch);
    }

    Ok(VerifiedRecoveryStagingArtifact {
        manifest: stored_manifest,
        repository_image: Bytes::from(repository_image),
    })
}

/// Remove a staging artifact and durably record the directory entry removal.
///
/// Cleanup is idempotent: a missing file is already removed.
pub(crate) fn delete_recovery_staging_artifact(path: &Path) -> Result<(), RecoveryStagingError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(io_error(path, source)),
    }
    let parent = artifact_parent(path)?;
    sync_parent_directory(parent).map_err(|source| io_error(parent, source))
}

fn artifact_parent(path: &Path) -> Result<&Path, RecoveryStagingError> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            io_error(
                path,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "recovery staging path has no parent directory",
                ),
            )
        })
}

fn io_error(path: &Path, source: io::Error) -> RecoveryStagingError {
    RecoveryStagingError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn sync_parent_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

fn sha256(image: &[u8]) -> [u8; DIGEST_LEN] {
    let value = digest(&SHA256, image);
    let mut bytes = [0_u8; DIGEST_LEN];
    bytes.copy_from_slice(value.as_ref());
    bytes
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use super::*;

    fn expectation() -> RecoveryStagingExpectation {
        RecoveryStagingExpectation::new(
            17,
            29,
            HistoryMetadata {
                version: 41,
                freshness: -3,
            },
            TerminalCut::new([7; JOURNAL_ID_LEN], 11, [13; DIGEST_LEN], [19; DIGEST_LEN]),
        )
    }

    #[test]
    fn write_and_verify_binds_the_complete_recovery_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.stage");
        let repository_image = b"durable repository snapshot";
        let expected = expectation();

        let written = write_recovery_staging_artifact(&path, expected, repository_image).unwrap();
        assert_eq!(written.expectation().attempt_id(), (17, 29));
        assert_eq!(
            written.expectation().repository_metadata(),
            HistoryMetadata {
                version: 41,
                freshness: -3,
            }
        );
        assert_eq!(
            written.expectation().terminal_cut(),
            expected.terminal_cut()
        );
        assert_eq!(written.content_len(), repository_image.len() as u64);
        assert_eq!(written.content_digest(), &sha256(repository_image));

        let verified = verify_recovery_staging_artifact(&path, written).unwrap();
        assert_eq!(verified.manifest(), written);
        assert_eq!(verified.repository_image().as_ref(), repository_image);
        assert_eq!(
            verified.into_repository_image(),
            Bytes::from_static(repository_image)
        );
    }

    #[test]
    fn verify_rejects_a_different_attempt_metadata_or_terminal_cut() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.stage");
        let expected = expectation();
        let written = write_recovery_staging_artifact(&path, expected, b"snapshot").unwrap();

        let wrong_attempt = RecoveryStagingExpectation::new(
            17,
            30,
            expected.repository_metadata(),
            expected.terminal_cut(),
        );
        let wrong_attempt_manifest = RecoveryStagingManifest::new(
            wrong_attempt,
            written.content_len(),
            *written.content_digest(),
        );
        assert!(matches!(
            verify_recovery_staging_artifact(&path, wrong_attempt_manifest),
            Err(RecoveryStagingError::EnvelopeMismatch)
        ));

        let wrong_metadata = RecoveryStagingExpectation::new(
            17,
            29,
            HistoryMetadata {
                version: 42,
                freshness: -3,
            },
            expected.terminal_cut(),
        );
        let wrong_metadata_manifest = RecoveryStagingManifest::new(
            wrong_metadata,
            written.content_len(),
            *written.content_digest(),
        );
        assert!(matches!(
            verify_recovery_staging_artifact(&path, wrong_metadata_manifest),
            Err(RecoveryStagingError::EnvelopeMismatch)
        ));

        let wrong_cut = RecoveryStagingExpectation::new(
            17,
            29,
            expected.repository_metadata(),
            TerminalCut::new([7; JOURNAL_ID_LEN], 12, [13; DIGEST_LEN], [19; DIGEST_LEN]),
        );
        let wrong_cut_manifest = RecoveryStagingManifest::new(
            wrong_cut,
            written.content_len(),
            *written.content_digest(),
        );
        assert!(matches!(
            verify_recovery_staging_artifact(&path, wrong_cut_manifest),
            Err(RecoveryStagingError::EnvelopeMismatch)
        ));
    }

    #[test]
    fn verify_rejects_corrupted_repository_content() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.stage");
        let expected = expectation();
        let written = write_recovery_staging_artifact(&path, expected, b"snapshot").unwrap();

        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();

        assert!(matches!(
            verify_recovery_staging_artifact(&path, written),
            Err(RecoveryStagingError::ContentDigestMismatch)
        ));
    }

    #[test]
    fn delete_is_durable_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.stage");
        write_recovery_staging_artifact(&path, expectation(), b"snapshot").unwrap();

        delete_recovery_staging_artifact(&path).unwrap();
        assert!(!path.exists());
        delete_recovery_staging_artifact(&path).unwrap();
    }
}
