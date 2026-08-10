use std::{collections::BTreeMap, fs::OpenOptions, io::Write, path::Path};

use tempfile::TempDir;

use super::{
    HistoryMetadata,
    recovery_staging::{
        RecoveryStagingExpectation, delete_recovery_staging_artifact,
        verify_recovery_staging_artifact, write_recovery_staging_artifact,
    },
    terminal_journal::{TerminalCut, TerminalJournal},
    terminal_journal_sqlite::{
        DurableRecoveryArtifactIntent, DurableRecoveryAttempt, DurableRecoveryParticipant,
        DurableRecoveryPhase, DurableRecoveryRepositoryMetadata, DurableRecoveryTarget,
        DurableRecoveryWitness, SqliteTerminalJournalStore,
    },
};

const ATTEMPT_ID: [u8; 16] = [41; 16];
const REPOSITORY_IMAGE: &[u8] = b"repository snapshot after strict recovery";

struct CrashFixture {
    root: TempDir,
    journal_path: std::path::PathBuf,
    staging_path: std::path::PathBuf,
    cut: TerminalCut,
    attempt: DurableRecoveryAttempt,
}

impl CrashFixture {
    fn new(phase: DurableRecoveryPhase) -> Self {
        let root = TempDir::new().unwrap();
        let cut = {
            let journal =
                TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
            journal.terminal_cut()
        };
        let attempt = recovery_attempt(cut, phase);
        let journal_path = root
            .path()
            .join("strict-terminal-journal")
            .join(format!("topic-{}.sqlite3", hex::encode("channels")));
        let staging_path = root.path().join("strict-recovery.stage");
        Self {
            root,
            journal_path,
            staging_path,
            cut,
            attempt,
        }
    }

    fn open_store(&self) -> SqliteTerminalJournalStore {
        SqliteTerminalJournalStore::open(&self.journal_path, "channels").unwrap()
    }

    fn open_journal(&self) -> TerminalJournal {
        TerminalJournal::load(Some(self.root.path().to_path_buf()), "channels").unwrap()
    }

    fn stage(&self) -> DurableRecoveryArtifactIntent {
        let expectation = RecoveryStagingExpectation::new(
            u64::from_be_bytes(ATTEMPT_ID[..8].try_into().unwrap()),
            u64::from_be_bytes(ATTEMPT_ID[8..].try_into().unwrap()),
            HistoryMetadata {
                version: 9_540,
                freshness: -17,
            },
            self.cut,
        );
        let manifest =
            write_recovery_staging_artifact(&self.staging_path, expectation, REPOSITORY_IMAGE)
                .unwrap();
        DurableRecoveryArtifactIntent::new(
            ATTEMPT_ID,
            self.staging_path.clone(),
            *manifest.content_digest(),
            manifest.content_len(),
            DurableRecoveryRepositoryMetadata::new(9_540, -17),
            self.cut,
        )
    }

    fn prepare(
        &self,
        store: &mut SqliteTerminalJournalStore,
        intent: &DurableRecoveryArtifactIntent,
    ) {
        store
            .prepare_recovery_install(
                std::iter::empty(),
                8,
                &BTreeMap::new(),
                &self.cut,
                &self.attempt,
                intent,
            )
            .unwrap();
    }
}

fn recovery_attempt(cut: TerminalCut, phase: DurableRecoveryPhase) -> DurableRecoveryAttempt {
    let first = DurableRecoveryParticipant::new(1, 101);
    let donor = DurableRecoveryParticipant::new(4, 404);
    DurableRecoveryAttempt::new(
        ATTEMPT_ID,
        phase,
        2,
        Some(DurableRecoveryTarget::new(
            9_540,
            -17,
            *cut.terminal_set_digest(),
        )),
        vec![
            DurableRecoveryWitness::new(first, cut),
            DurableRecoveryWitness::new(donor, cut),
        ],
        vec![first, donor],
        Some(0),
        Some(first),
        Some(cut),
        vec![],
    )
    .unwrap()
}

fn assert_restart_is_fenced(store: &SqliteTerminalJournalStore) {
    assert!(
        store.load_recovery_attempt().unwrap().is_some(),
        "an incomplete durable attempt must keep startup outside Healthy"
    );
}

fn replace_repository_file(path: &Path, image: &[u8]) {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .unwrap();
    file.write_all(image).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn crash_after_staging_fsync_preserves_the_active_attempt_fence() {
    let fixture = CrashFixture::new(DurableRecoveryPhase::FetchingRepositorySnapshot);
    {
        let mut store = fixture.open_store();
        store.persist_recovery_attempt(&fixture.attempt).unwrap();
        let intent = fixture.stage();
        let expected = super::recovery_staging::RecoveryStagingManifest::new(
            RecoveryStagingExpectation::new(
                u64::from_be_bytes(ATTEMPT_ID[..8].try_into().unwrap()),
                u64::from_be_bytes(ATTEMPT_ID[8..].try_into().unwrap()),
                HistoryMetadata {
                    version: 9_540,
                    freshness: -17,
                },
                fixture.cut,
            ),
            intent.content_length(),
            *intent.content_digest(),
        );
        verify_recovery_staging_artifact(&fixture.staging_path, expected).unwrap();
        assert!(store.load_recovery_artifact_intent().unwrap().is_none());
    }

    let reopened = fixture.open_store();
    assert_restart_is_fenced(&reopened);
    assert!(reopened.load_recovery_artifact_intent().unwrap().is_none());
}

#[test]
fn crash_after_atomic_journal_preparation_rolls_forward_the_exact_intent() {
    let fixture = CrashFixture::new(DurableRecoveryPhase::Installing);
    let intent = fixture.stage();
    {
        let mut store = fixture.open_store();
        store.persist_recovery_attempt(&fixture.attempt).unwrap();
        fixture.prepare(&mut store, &intent);
    }

    let reopened = fixture.open_store();
    assert_restart_is_fenced(&reopened);
    assert_eq!(
        reopened.load_recovery_artifact_intent().unwrap(),
        Some(intent)
    );
    let (_, cut, epoch, version, retired, pending, freshness) =
        reopened.load().unwrap().unwrap().into_parts();
    assert_eq!(cut, fixture.cut);
    assert_eq!(epoch, 8);
    assert_eq!(version, 9_540);
    assert_eq!(freshness, -17);
    assert!(retired.is_empty());
    assert!(pending);
    {
        let journal = fixture.open_journal();
        assert_eq!(journal.terminal_cut(), fixture.cut);
        assert!(journal.pending_repository_image_install().is_some());
        assert!(
            super::recovery_v8_runtime::restore_coordinator(&journal)
                .unwrap()
                .is_some(),
            "the crash fixture must restore through the production coordinator path"
        );
    }
}

#[test]
fn crash_after_repository_replacement_still_requires_durable_verification() {
    let fixture = CrashFixture::new(DurableRecoveryPhase::Installing);
    let intent = fixture.stage();
    {
        let mut store = fixture.open_store();
        store.persist_recovery_attempt(&fixture.attempt).unwrap();
        fixture.prepare(&mut store, &intent);
    }
    replace_repository_file(
        &fixture.root.path().join("repository.snapshot"),
        REPOSITORY_IMAGE,
    );

    let reopened = fixture.open_store();
    assert_restart_is_fenced(&reopened);
    assert!(reopened.load().unwrap().unwrap().into_parts().5);
    assert_eq!(
        reopened.load_recovery_artifact_intent().unwrap(),
        Some(intent)
    );
}

#[test]
fn crash_after_verification_keeps_the_exact_install_pending() {
    let fixture = CrashFixture::new(DurableRecoveryPhase::Installing);
    let intent = fixture.stage();
    {
        let mut store = fixture.open_store();
        store.persist_recovery_attempt(&fixture.attempt).unwrap();
        fixture.prepare(&mut store, &intent);
        store
            .persist_recovery_attempt(&recovery_attempt(
                fixture.cut,
                DurableRecoveryPhase::Verifying,
            ))
            .unwrap();
    }

    let mut reopened = fixture.open_store();
    assert_restart_is_fenced(&reopened);
    let wrong_cut = TerminalCut::new([42; 16], 8, [43; 32], [44; 32]);
    assert!(
        reopened
            .finalize_recovery_install(
                &ATTEMPT_ID,
                8,
                DurableRecoveryRepositoryMetadata::new(9_540, -17),
                &wrong_cut,
            )
            .is_err(),
        "verification of all four terminal-cut fields is required"
    );
    assert_restart_is_fenced(&reopened);
    assert!(reopened.load().unwrap().unwrap().into_parts().5);
    assert_eq!(
        reopened.load_recovery_artifact_intent().unwrap(),
        Some(intent)
    );
}

#[test]
fn durable_completion_is_last_and_artifact_cleanup_is_restart_safe() {
    let fixture = CrashFixture::new(DurableRecoveryPhase::Installing);
    let intent = fixture.stage();
    {
        let mut store = fixture.open_store();
        store.persist_recovery_attempt(&fixture.attempt).unwrap();
        fixture.prepare(&mut store, &intent);
        store
            .persist_recovery_attempt(&recovery_attempt(
                fixture.cut,
                DurableRecoveryPhase::Verifying,
            ))
            .unwrap();
        store
            .finalize_recovery_install(
                &ATTEMPT_ID,
                8,
                DurableRecoveryRepositoryMetadata::new(9_540, -17),
                &fixture.cut,
            )
            .unwrap();
    }

    let reopened = fixture.open_store();
    assert!(reopened.load_recovery_attempt().unwrap().is_none());
    assert!(reopened.load_recovery_artifact_intent().unwrap().is_none());
    assert!(!reopened.load().unwrap().unwrap().install_pending());
    assert!(fixture.staging_path.exists());
    delete_recovery_staging_artifact(&fixture.staging_path).unwrap();
    delete_recovery_staging_artifact(&fixture.staging_path).unwrap();
}
