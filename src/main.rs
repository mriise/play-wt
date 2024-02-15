use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use data_encoding::{BASE64, BASE64URL};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::{select, sync::mpsc::Receiver};
use tracing::{debug, error, info, info_span, Instrument};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use wtransport::{
    endpoint::{endpoint_side::Server, IncomingSession},
    Certificate, Endpoint, ServerConfig,
};

use notify_debouncer_full::{new_debouncer, DebouncedEvent, Debouncer, FileIdMap, NoCache};

#[tokio::main]
async fn main() -> Result<()> {
    logger();
    let (files, _watcher, notify_receiver) = files()?;

    let certificate = Certificate::self_signed(&["localhost", "127.0.0.1", "::1"]);

    info!(
        "Certhash: {}",
        BASE64.encode(certificate.hashes()[0].as_ref())
    );

    let config = ServerConfig::builder()
        .with_bind_config(wtransport::config::IpBindConfig::InAddrAnyDual, 41582)
        .with_certificate(certificate)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();

    let connection = Endpoint::server(config)?;

    let server = WebTransportServer { ep: connection };

    select! {
        result = server.serve() => {
            error!("{:?}", result)
        }
        result = hash_files(files, notify_receiver) => {
            error!("{:?}", result)
        }
    }

    Ok(())
}

pub struct WebTransportServer {
    pub(crate) ep: Endpoint<Server>,
}

impl WebTransportServer {
    pub async fn serve(self) -> Result<()> {
        info!(
            "Server running on https://{}",
            self.ep.local_addr().unwrap()
        );

        for id in 0.. {
            let incoming_session = self.ep.accept().await;

            tokio::spawn(
                Self::handle_incoming_session(incoming_session)
                    .instrument(info_span!("Connection", id)),
            );
        }

        Ok(())
    }

    async fn handle_incoming_session(session: IncomingSession) {
        async fn handle_inner(session: IncomingSession) -> Result<()> {
            let mut buffer = vec![0; 65536].into_boxed_slice();
            let session_request = session.await?;

            info!(
                "New session: Authority: '{}', Path: '{}'",
                session_request.authority(),
                session_request.path()
            );

            let connection = session_request.accept().await?;

            info!("Waiting for data from client...");
            loop {
                tokio::select! {
                    stream = connection.accept_bi() => {
                        let mut stream = stream?;
                        info!("Accepted BI stream");

                        let bytes_read = match stream.1.read(&mut buffer).await? {
                            Some(bytes_read) => bytes_read,
                            None => continue,
                        };

                        let str_data = std::str::from_utf8(&buffer[..bytes_read])?;

                        info!("Received (bi) '{str_data}' from client");

                        stream.0.write_all(b"ACK").await?;
                    }
                    dgram = connection.receive_datagram() => {
                        let dgram = dgram?;
                        let str_data = std::str::from_utf8(&dgram)?;

                        info!("Received (dgram) '{str_data}' from client");

                        connection.send_datagram(b"ACK")?;
                    }
                }
            }
        }

        info!("Session Ended: {:?}", handle_inner(session).await);
    }
}

fn logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::DEBUG.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(env_filter)
        .init();
}

async fn hash_files(files: Vec<PathBuf>, mut notify_receiver: Receiver<DebouncedEvent>) -> Result<()> {
    let mut hasher = blake3::Hasher::new();

    fn hash_n_copy(hasher: &mut blake3::Hasher, path: &PathBuf) -> Result<()> {
        hasher.update_mmap_rayon(&path)?;
        let mut new_path = path.clone();
        new_path.pop();
        // TODO: use CID
        new_path.push("hashed");
        let hash_id = BASE64URL.encode(hasher.finalize().as_bytes());
        new_path.push(&hash_id);

        info!(
            "adding {} to hashed files as {:?}",
            &path.to_string_lossy(),
            hash_id
        );
        fs::copy(path, new_path)?;

        hasher.reset();
        Ok(())
    }
    for path in files {
        // todo: errors much?
        hash_n_copy(&mut hasher, &path);
    }

    loop {
        let event = notify_receiver
            .recv()
            .await
            .context("file watcher closed unexpectedly")?;
        match event.kind {
            // re-hash if changed or new
            notify::EventKind::Create(ck) => match ck {
                notify::event::CreateKind::File => debug!("file added"),
                notify::event::CreateKind::Folder => {
                    debug!("Folder added! TODO: zip and then hash")
                }
                notify::event::CreateKind::Any | notify::event::CreateKind::Other => {
                    hash_n_copy(&mut hasher, &event.paths[0]).map_err(|e| error!("{} {:?}", e, event.paths));
                }
            },
            notify::EventKind::Modify(mk) => match mk {
                notify::event::ModifyKind::Data(_) => debug!("file modified"),
                // any event catches too much, do nothing
                notify::event::ModifyKind::Any => (),
                | notify::event::ModifyKind::Metadata(_)
                | notify::event::ModifyKind::Name(_)
                | notify::event::ModifyKind::Other => debug!("TODO modify event {:?}", event.paths),
            },
            // remove
            notify::EventKind::Remove(_) => debug!("TODO file removed"),
            // do nothing otherwise
            notify::EventKind::Any | notify::EventKind::Access(_) | notify::EventKind::Other => (),
        }
    }
}

fn files() -> Result<(Vec<PathBuf>, Debouncer<RecommendedWatcher, FileIdMap>, Receiver<DebouncedEvent>)> {
    debug!("building folder structure");

    let path = std::env::current_dir()?.join("wtplay-files");
    touch(&path);
    let hashed_path = path.join("hashed");
    touch(&hashed_path);

    // read & watch file
    let files = fs::read_dir(&path)?;

    //
    let (sender, receiver) = tokio::sync::mpsc::channel::<DebouncedEvent>(12);

    let mut debouncer = new_debouncer(Duration::from_secs(1), None, move |res| match res {
        Ok(debounced) => {
            for event in debounced {
                let _ = sender
                .blocking_send(event)
                .map_err(|e| error!("File watcher failed to send event {:?}", e));
            }

        }
        Err(e) => error!("watch error: {:?}", e),
    })?;


    info!(
        "Watching for new files to serve in: {} ",
        path.to_string_lossy()
    );
    debouncer.watcher().watch(&path, RecursiveMode::NonRecursive)?;

    // get all accessable files and not the hashed folder
    let iter = files.filter_map(|file| match file {
        Ok(file) => {
            if file.path() != hashed_path {
                Some(file)
            } else {
                None
            }
        }
        Err(_) => None,
    });

    let mut vec = Vec::new();
    let mut s = String::new();
    for file in iter {
        vec.push(file.path());
        s.push_str(&format!(
            "{}, ",
            file.file_name()
                .to_str()
                .context("couldnt encode file name to utf-8")?
        ));
    }

    Ok((vec, debouncer, receiver))
}

fn touch(path: &Path) {
    match fs::read_dir(&path) {
        Ok(_) => (),
        Err(_) => {
            let _ = fs::create_dir(&path).map_err(|e| error!("{e}"));
        }
    }
}
