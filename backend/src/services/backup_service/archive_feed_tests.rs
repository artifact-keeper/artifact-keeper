//! When the backup opens each artifact stream (#5858).

use super::*;
use crate::services::storage_service::{FilesystemBackend, StorageBackend};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Filesystem storage whose streams are slow to read and counted while open.
struct CountedStreams {
    inner: FilesystemBackend,
    open: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

struct OpenStream(Arc<AtomicUsize>);

impl Drop for OpenStream {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl StorageBackend for CountedStreams {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        self.inner.put(key, content).await
    }
    async fn get(&self, key: &str) -> Result<Bytes> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        self.inner.copy(source, dest).await
    }
    async fn size(&self, key: &str) -> Result<u64> {
        self.inner.size(key).await
    }
    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let bytes = self.inner.get(key).await?;
        let now = self.open.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        let open = OpenStream(self.open.clone());
        let chunks: Vec<Bytes> = bytes.chunks(4096).map(Bytes::copy_from_slice).collect();
        Ok(futures::stream::iter(chunks)
            .then(move |chunk| {
                let _open = &open;
                async move {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    Ok(chunk)
                }
            })
            .boxed())
    }
}

/// The writer holds one artifact stream at a time. Before #5858 the feeder
/// opened the next ones while the writer was still busy, and a queued GET's
/// bulk timeout ran while it waited.
#[tokio::test]
async fn backup_opens_each_artifact_only_when_the_writer_is_ready_for_it_5858() {
    let dir = std::env::temp_dir().join(format!("bk-feed-5858-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (open, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let backend = CountedStreams {
        inner: FilesystemBackend::new(dir.clone()),
        open: open.clone(),
        peak: peak.clone(),
    };
    let mut objects = Vec::new();
    for i in 0..5u8 {
        let key = format!("feed/object-{i}");
        let bytes = vec![i; 16 * 1024];
        backend.put(&key, Bytes::from(bytes.clone())).await.unwrap();
        objects.push((key, bytes));
    }
    let pool = PgPool::connect_lazy("postgres://fake:fake@localhost/fake").unwrap();
    let service = BackupService::new(pool, Arc::new(StorageService::new(Arc::new(backend))));
    let backup = Backup {
        id: Uuid::new_v4(),
        backup_type: BackupType::Full,
        status: BackupStatus::InProgress,
        storage_path: None,
        size_bytes: None,
        artifact_count: None,
        started_at: None,
        completed_at: None,
        error_message: None,
        metadata: None,
        created_by: None,
        created_at: Utc::now(),
        payload_checksum: None,
    };
    let artifacts = objects
        .iter()
        .map(|(key, _)| ArtifactObject {
            storage_key: key.clone(),
            locations: vec![StorageLocation {
                backend: "filesystem".into(),
                path: dir.display().to_string(),
            }],
        })
        .collect();
    let table = (
        "users".to_string(),
        serde_json::to_vec(&serde_json::json!([])).unwrap(),
    );

    let (pieces, pieces_rx) = mpsc::channel(ARCHIVE_QUEUE_DEPTH);
    let (written, progress) = watch::channel(0);
    let writer = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        let manifest = write_archive(pieces_rx, &mut out, written);
        (manifest, out)
    });
    let (count, unreadable) = service
        .feed_archive(
            (pieces, progress),
            &backup,
            &["users"],
            vec![table],
            artifacts,
            BackupContents::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let (manifest, archive) = writer.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    manifest.unwrap();
    assert_eq!((count, unreadable.len()), (5, 0));
    assert_eq!(open.load(Ordering::SeqCst), 0);
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "artifact streams were opened while the writer was busy with another"
    );
    let entries = BackupService::extract_entries(&archive).unwrap();
    for (key, bytes) in &objects {
        let path = std::path::PathBuf::from(format!("artifacts/{key}"));
        let entry = entries.iter().find(|(p, _)| *p == path).unwrap();
        assert_eq!(&entry.1, bytes);
    }
}
