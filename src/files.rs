use std::{
    path::{self, Path},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use data_encoding::BASE64URL;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use notify_debouncer_full::{new_debouncer, DebouncedEvent, Debouncer, FileIdMap};
use redb::{Database, ReadableTable};
use std::result::Result::Ok;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info, info_span, warn};

pub type FileMetaValue<'a> = (u64, &'a str);

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FileMeta {
    size: u64,
    name: String,
}

impl<'a> From<&'a FileMeta> for FileMetaValue<'a> {
    fn from(value: &'a FileMeta) -> Self {
        (value.size, &value.name)
    }
}

pub struct FileManager {
    db: Arc<Database>,
    fs_rx: Receiver<DebouncedEvent>,
}

impl FileManager {
    pub fn new(
        fs_root: impl AsRef<Path>,
        db_path: impl AsRef<Path>,
        fs_rx: Receiver<DebouncedEvent>,
    ) -> anyhow::Result<Self> {
        let mut db = Database::create(db_path)?;

        db.check_integrity()?;

        // make sure our table exists
        let db_write = db.begin_write()?;
        {
            let _fs_table = db_write.open_table(crate::FILE_DB)?;
        }
        db_write.commit()?;

        let fm = FileManager {
            db: Arc::new(db),
            fs_rx,
        };

        // add all files that currently exist in folder
        let dir = std::fs::read_dir(&fs_root)?;
        for path in dir {
            match path {
                std::result::Result::Ok(p) => {
                    let _ = fm
                        .add_file(&p.path())
                        .map_err(|e| error!("Failed to add file on startup {e}"));
                }
                Err(e) => {
                    error!("Failed to read file path on startup {e}")
                }
            }
        }
        // TODO: remove all hashes in DB that were removed since last run

        Ok(fm)
    }

    /// Debouncer must not be dropped till end of program (always listen for file changes)
    pub fn new_fs_notify(
        watch_path: impl AsRef<Path>,
    ) -> anyhow::Result<(
        Debouncer<RecommendedWatcher, FileIdMap>,
        Receiver<DebouncedEvent>,
    )> {
        // 16 is arbitrary outside of being a power of 2 and greater than 4
        let (sender, receiver) = tokio::sync::mpsc::channel::<DebouncedEvent>(16);

        // TODO: play with timeout for performance/effeciency balance
        let mut debouncer = new_debouncer(Duration::from_secs(1), None, move |res| match res {
            std::result::Result::Ok(debounced) => {
                for event in debounced {
                    let _ = sender
                        .blocking_send(event)
                        .map_err(|e| error!("File watcher failed to send event {:?}", e));
                }
            }
            Err(e) => error!("File watch error: {:?}", e),
        })?;

        debouncer
            .watcher()
            .watch(watch_path.as_ref(), RecursiveMode::NonRecursive)?;

        Ok((debouncer, receiver))
    }

    /// Creates a strong ref to the database
    pub fn db_ref(&self) -> Arc<Database> {
        self.db.clone()
    }

    pub async fn start(mut self) -> anyhow::Result<()> {
        loop {
            let DebouncedEvent { event, .. } = self
                .fs_rx
                .recv()
                .await
                .context("File watcher closed unexpectedly")?;

            let span = info_span!("File Event");
            span.in_scope(|| self.handle_event(event));
        }
    }

    fn handle_event(&self, event: Event) {
        let Event { kind, paths, .. } = event;
        match kind {
            // creation or modification of any kind is either ignored, added, or updated
            notify::EventKind::Create(_) | notify::EventKind::Modify(_) => {
                for path in paths {
                    let _ = self
                        .add_file(&path)
                        .map_err(|e| error!("File add failed: {e}"));
                }
            }
            // NOTE: remove might sometimes force a new key to be added when its not necessary
            // TODO: this may remove a renamed file that was recently added
            //       assuming it was added THEN removed
            notify::EventKind::Remove(_) => {
                for path in paths {
                    let _ = self
                        .remove_file(&path)
                        .map_err(|e| error!("File remove failed: {e}"));
                }
            }
            // no files changed with these (or is too blunt of a hammer)
            notify::EventKind::Access(_) | notify::EventKind::Any | notify::EventKind::Other => (),
        }
    }

    /// no-op if sub-dir or symlink
    fn add_file(&self, path: &Path) -> anyhow::Result<()> {
        let meta = std::fs::metadata(path)?;
        let len = meta.len();

        // do nothing if there isnt anything to hash
        // this check is done here for convenience to just use the `Any` event
        // we dont recursively notify sub-dir's anyway
        if meta.is_dir() {
            warn!("Folder added under Files, sub directories and their contents are ignored");
            return Ok(());
        }

        // ignore symlinks
        if path.is_symlink() {
            warn!("Symbolic link added to Files, it will be ignored");
            return Ok(());
        }

        let hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update_mmap_rayon(&path)?;
            hasher.finalize()
        };

        let name = path_to_filename(path)?;

        // add file to db
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(crate::FILE_DB)?;
            table.insert(hash.as_bytes(), (len, name))?;
        }
        tx.commit()?;

        info!(
            hash = BASE64URL.encode(hash.as_bytes()),
            path = String::from(path.to_string_lossy())
        );
        Ok(())
    }

    //
    fn remove_file(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        let mut table = tx.open_table(crate::FILE_DB)?;

        // search db for any matching file name and remove from table
        let matching: Vec<([u8; 32], String)> = {
            table
                .iter()?
                .filter_map(|k| match (k, path_to_filename(path.as_ref())) {
                    (Ok(value), Ok(r_name)) => {
                        let v_name = value.1.value().1;
                        if v_name == r_name {
                            Some((*value.0.value(), String::from(r_name)))
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .collect()
        };

        // remove all refrences
        for (hash, filename) in matching {
            table.remove(&hash)?;
            let span = info_span!("Remove File");
            span.in_scope(|| info!(hash = BASE64URL.encode(&hash), filename))
        }

        Ok(())
    }
}

fn path_to_filename<'a>(path: &'a Path) -> anyhow::Result<&'a str> {
    path.file_name()
        .context(format!("File name not found! {}", path.to_string_lossy()))?
        .to_str()
        .context("File name was unable to be encoded into UTF-8")
}
