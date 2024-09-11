use crate::FILE_TABLE;

use std::{
    io::{self, Write},
    path::{self, Path},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use sqlx::{prelude::*, query_as, Sqlite, SqlitePool, Transaction};

use anyhow::Context;
use data_encoding::BASE64URL;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use notify_debouncer_full::{new_debouncer, DebounceEventResult, DebouncedEvent, Debouncer, FileIdMap};
use sqlx::{
    query,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Encode, SqliteConnection,
};
use sqlx::{ConnectOptions, Connection};
use std::result::Result::Ok;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info, info_span, warn};

#[derive(Debug)]
struct FileRow {
    hash: String,
    path: String,
    size: i64,
}

pub struct FileManager {
    db: SqlitePool,
    fs_rx: Receiver<DebouncedEvent>,
}

impl FileManager {
    pub async fn new(
        fs_root: impl AsRef<Path>,
        db: SqlitePool,
        fs_rx: Receiver<DebouncedEvent>,
    ) -> anyhow::Result<Self> {
        // hashes are valid primary keys, and rowids arent needed
        let q = format!("CREATE TABLE IF NOT EXISTS {FILE_TABLE} (Hash TINYTEXT PRIMARY KEY, Path TEXT, Size INTEGER) WITHOUT ROWID");
        let _ = db.execute(&*q).await?;

        let fm = FileManager { db:db.clone(), fs_rx };
        let mut added_hashes = Vec::new(); 

        // add all files that currently exist in folder
        let dir = std::fs::read_dir(&fs_root)?;
        for path in dir {
            match path {
                std::result::Result::Ok(p) => {
                    let res = fm
                        .add_file(&p.path())
                        .await
                        .map_err(|e| error!("Failed to add file on startup {e}"));
                    if let Ok(Some(hash)) = res {
                        added_hashes.push(BASE64URL.encode(&hash));
                    }
                }
                Err(e) => {
                    error!("Failed to read file path on startup {e}")
                }
            }
        }
        let mut tx = db.begin().await?;
        added_hashes.sort_unstable();
        async fn remove_missing_files(tx: &mut Transaction<'static, Sqlite>, added_hashes: Vec<String>) -> bool {
            let q = format!("SELECT * FROM {FILE_TABLE}");
            let q = query(&*q);
            if let Ok(mut rows) = tx.fetch_all(q).await {
                rows.retain(|row| {
                    let row_hash: String = row.get(0);
                    // keep this row saved, there is no existing file for it in the folder
                    added_hashes.binary_search(&row_hash).is_err()
                });
                // fuck you, no fancy SQL join-remove
                for row in rows {
                    let row_hash: String = row.get(0);

                    let q = format!("DELETE FROM {FILE_TABLE} WHERE Hash = $1");
                    let q = query(&q).bind(row_hash);
                    if tx.execute(q).await.is_err() {
                        return false
                    }
                }
            }
            true
        }
        // rollabck if we had an issue with removing the ones we had
        if remove_missing_files(&mut tx, added_hashes).await {
            tx.commit().await?
        } else {
            error!("Tried removing files from database that were removed from folder while service was offline.");
            tx.rollback().await?
        }

        Ok(fm)
    }

    /// Debouncer must not be dropped till end of program (always listen for file changes)
    pub fn new_fs_notify(
        watch_path: impl AsRef<Path>,
        recursive: bool,
    ) -> anyhow::Result<(
        Debouncer<RecommendedWatcher, FileIdMap>,
        Receiver<DebouncedEvent>,
    )> {
        // 16 is arbitrary outside of being a power of 2 and greater than 4
        let (sender, receiver) = tokio::sync::mpsc::channel::<DebouncedEvent>(16);

        // TODO: play with timeout for performance/effeciency balance
        let mut debouncer = new_debouncer(Duration::from_secs(2), None, move |res: DebounceEventResult| match res {
            std::result::Result::Ok(debounced) => {
                for event in debounced.into_iter() {
                    let _ = sender
                        .blocking_send(event)
                        .map_err(|e| error!("File watcher failed to send event {:?}", e));
                }
            }
            Err(e) => error!("File watch error: {:?}", e),
        })?;

        let recursive_mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        debouncer
            .watcher()
            .watch(watch_path.as_ref(), recursive_mode)?;

        Ok((debouncer, receiver))
    }

    // /// Creates a strong ref to the database
    // pub fn db_ref(&self) -> Arc<S> {
    //     self.db.clone()
    // }

    pub async fn start(mut self) -> anyhow::Result<()> {
        loop {
            let DebouncedEvent { event, .. } = self
                .fs_rx
                .recv()
                .await
                .context("File watcher closed unexpectedly")?;

            let span = info_span!("File Event");
            let _entered = span.enter();
            self.handle_event(event).await
        }
    }

    async fn handle_event(&self, event: Event) {
        let Event { kind, paths, .. } = event;
        match kind {
            // creation or modification of any kind is either ignored, added, or updated
            notify::EventKind::Create(_) | notify::EventKind::Modify(_) => {
                for path in paths {
                    let _ = self
                        .add_file(&path)
                        .await
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
                        .await
                        .map_err(|e| error!("File remove failed: {e}"));
                }
            }
            // no files changed with these (or is too blunt of a hammer)
            notify::EventKind::Access(_) | notify::EventKind::Any | notify::EventKind::Other => (),
        }
    }

    /// no-op if sub-dir or symlink
    async fn add_file(&self, path: &Path) -> anyhow::Result<Option<[u8; 32]>> {
        // ignore non-existent files (file notifier sometimes does this)
        if !path.exists() {
            warn!(
                path = String::from(path.to_string_lossy()),
                "Path does not point to anything! (likely a buggy file watcher)"
            );
            return Ok(None);
        }


        let meta = std::fs::metadata(path)?;
        // god i hate this, why does sqlite not have u64???? 2^63 is ok enough for this though.
        let len = meta.len() as i64;

        // do nothing if there isnt anything to hash
        // this check is done here for convenience to just use the `Any` event
        // we dont recursively notify sub-dir's anyway
        if meta.is_dir() {
            warn!("Folder added under Files, sub directories and their contents are ignored");
            return Ok(None);
        }

        // ignore symlinks
        if path.is_symlink() {
            warn!("Symbolic link added to Files, it will be ignored");
            return Ok(None);
        }

        let hash = blake3::hash(&std::fs::read(&path)?);

        let name = path_to_filename(path)?;

        let q = format!("INSERT OR REPLACE INTO {FILE_TABLE} VALUES ($1, $2, $3)");
        let q = sqlx::query(&*q)
            .bind(BASE64URL.encode(hash.as_bytes()))
            .bind(name)
            .bind(len);
        let a = self.db.execute(q).await?;

        info!(
            hash = BASE64URL.encode(hash.as_bytes()),
            path = String::from(path.to_string_lossy())
        );
        Ok(Some(*hash.as_bytes()))
    }

    //
    async fn remove_file(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let q = format!("DELETE FROM {FILE_TABLE} WHERE Path = $1");

        let q = sqlx::query(&*q).bind(path_to_filename(path.as_ref())?);
        let a = self.db.execute(q).await?;

        // search db for any matching file name and remove from table

        Ok(())
    }
}

fn path_to_filename<'a>(path: &'a Path) -> anyhow::Result<&'a str> {
    path.file_name()
        .context(format!("File name not found! {}", path.to_string_lossy()))?
        .to_str()
        .context("File name was unable to be encoded into UTF-8")
}
