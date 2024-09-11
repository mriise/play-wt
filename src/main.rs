use anyhow::Result;
use certs::CertManager;
use const_format::concatcp;
use sqlx::{Executor, SqliteConnection, SqlitePool, Row};
use std::{
    fs::{self, File},
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc, Weak},
    time::Duration,
};

use data_encoding::BASE64URL;
use tokio::{
    fs::create_dir,
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};
use tracing::{debug, error, error_span, field::debug, info, info_span, warn, Instrument};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use wtransport::{
    endpoint::{endpoint_side::Server, IncomingSession},
    Connection, Endpoint, Identity, RecvStream, SendStream, ServerConfig, VarInt,
};

mod auth;
mod certs;
mod files;
mod messages;

use messages::{FetchResponse, Signal, SignalRequest};

use crate::{
    files::FileManager,
    messages::{send_response, ErrorResponse},
};

// TODO: DB eats up more space than it seemingly needs. maybe switch to sqlite3?

const APP_PREFIX: &str = "playwt";

pub const FILE_TABLE: &str = concatcp!(APP_PREFIX, "_files");
pub const AUTH_TABLE: &str = concatcp!(APP_PREFIX, "_auth");
pub const UPLOAD_TABLE: &str = concatcp!(APP_PREFIX, "_uploads");

// TODO: add readme in internal folder for curious users
const INTERNAL_FOLDER: &str = concatcp!(APP_PREFIX, "_internal");
const INTERNAL_UPLOADED_FILES: &str = "uploaded";
const INTERNAL_CERTS: &str = "certs";
const INTERNAL_CERT_HISTORY_TABLE: &str = "_CERTIFICATE_HISTORY.csv";
const FILES_FOLDER: &str = concatcp!(APP_PREFIX, "_files");

#[tokio::main]
async fn main() -> Result<()> {
    logger();

    let internal_root = build_root_folder(INTERNAL_FOLDER)?;
    let upload_root = build_internal_folder(&internal_root, INTERNAL_UPLOADED_FILES)?;
    let cert_root = build_internal_folder(&internal_root, INTERNAL_CERTS)?;
    let fs_root = build_root_folder(FILES_FOLDER)?;

    let (_fs_watcher, fs_rx) = FileManager::new_fs_notify(&fs_root, false)?;
    let (_upld_watcher, upld_rx) = FileManager::new_fs_notify(&upload_root, false)?;

    let mut db_path = internal_root;
    db_path.push("databseV1.db");
    info!("{}", db_path.to_string_lossy());
    let db = init_db(db_path).await?;

    let fs_manager = FileManager::new(fs_root, db.clone(), fs_rx).await?;

    // let identity = Identity::self_signed(&["localhost", "127.0.0.1", "::1"])?;

    // identity.private_key().store_secret_pemfile(filepath);

    // self signed so our certhash should be the only one
    // let cert = &identity.certificate_chain().as_ref()[0];
    // info!(certhash = BASE64URL.encode(cert.hash().as_ref()),);

    let start_config = ActiveServerConfig {
        port: 4999,
        cert_root,
        keepalive: Some(Duration::from_secs(3)),
        subject_alt_names: vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ],
    };
    let server = WebTransportServer::new(db.clone(), start_config)?;

    select! {
        result = server.serve() => {
            error!("{:?}", result)
        }
        result = fs_manager.start() => {
            error!("{:?}", result)
        }
    }

    Ok(())
}

async fn upnp(local_addr: SocketAddr) -> Result<()> {
    // 2 weeks (our TLS cert expires then as well)
    const WEEK_DUR: u32 = 60 * 60 * 24 * 14;
    fn inner(local_addr: SocketAddr) -> Result<()> {
        use igd_next::*;
        use local_ip_address::local_ip;

        let iface = netdev::get_default_interface().map_err(|e| anyhow::format_err!("{e}"))?;
        debug!(default_interface =? iface);

        // OS gave us an ipv6 for webtransport, this likely means we can get our external IPv6 and log as an external address
        if local_addr.is_ipv6() {
            debug!(
                "Local IPv6 Address: https://[{}]:{}",
                local_addr.ip(),
                local_addr.port()
            );

            if let Some(ipv6) = iface.ipv6.first() {
                info!(
                    "External IPv6 Address: https://[{}]:{}",
                    ipv6.addr,
                    local_addr.port()
                );
            }
        }

        // Attempt to add ports to UPnP, just in case client can only use ip4
        info!("Asking Default Gateway for UPnP port");

        let local_ip4 = local_ip()?;

        // man i love rust!
        (|| -> anyhow::Result<()> {
            let gw = search_gateway(SearchOptions::default())?;
            // local ip4 (just incase our webtransport ip is v6)
            let local_ip4 = SocketAddr::new(local_ip4, local_addr.port());

            debug!("Adding UPnP port with ip4 {}", local_ip4);
            gw.add_port(
                PortMappingProtocol::UDP,
                local_addr.port(),
                local_ip4,
                WEEK_DUR,
                "play-wt",
            )?;
            info!(
                "External IPv4 Address: https://{}:{}",
                gw.get_external_ip()?,
                local_addr.port()
            );

            Ok(())
        })().map_err(|e| {
            if iface.ipv6.is_empty() {
                warn!("UPnP Failed. Enable UPnP on router and device and try again, or ensure ensure port {} is forwarded for {}", local_addr.port(), local_ip4);
            } else {
                warn!("UPnP Failed. Clients connecting through IPv4 may be unnable to connect. Enable UPnP on router and try again, or ensure ensure port {} is forwarded for {}", local_addr.port(), local_ip4);
            }
            debug!("{e}");
        }).ok();

        Ok(())
    }
    let span = error_span!("Net Startup");
    let _enter = span.enter();
    let _ = inner(local_addr).map_err(|e| error!("{e}"));
    info!("Finished!");

    Ok(())
}

pub struct WebTransportServer {
    ep: Arc<Endpoint<Server>>,
    db: SqlitePool,
    start_config: ActiveServerConfig,
}

#[derive(Debug, Clone)]
// TODO: other server config values as-needed
pub struct ActiveServerConfig {
    port: u16,
    keepalive: Option<Duration>,
    cert_root: PathBuf,
    /// subject alt name changes will only reflect on new certs
    subject_alt_names: Vec<String>,
}

impl WebTransportServer {
    fn new(db: SqlitePool, start_config: ActiveServerConfig) -> Result<Self> {
        // temporary ident until the cert manager takes over
        let temp_identity = Identity::self_signed(&start_config.subject_alt_names)?;

        let config = ServerConfig::builder()
            .with_bind_default(start_config.port)
            .with_identity(&temp_identity)
            .keep_alive_interval(start_config.keepalive)
            .build();

        let connection = Endpoint::server(config)?;

        Ok(Self {
            db,
            ep: Arc::new(connection),
            start_config,
        })
    }

    pub async fn serve(self) -> Result<()> {
        let _ = upnp(self.ep.local_addr()?).await.map_err(|e| error!("{e}"));

        let mut cert_manager = CertManager::new(self.start_config.clone()).await?;

        // clone out of the closure so rust doesnt get mad about moving self
        let endpoint_ref = self.ep.clone();
        // start running cert manager
        tokio::spawn(async move {
            cert_manager
                .start(endpoint_ref)
                .await
                .map_err(|e| error!("{e}"))
                .ok();
        });

        // accept sessoins
        for id in 0.. {
            let incoming_session = self.ep.accept().await;

            tokio::spawn(
                Self::handle_incoming_session(self.db.clone(), incoming_session)
                    .instrument(info_span!("Connection", id)),
            );
        }

        Ok(())
    }

    async fn handle_incoming_session(db_ref: SqlitePool, session: IncomingSession) {
        async fn handle_inner(db_ref: SqlitePool, session: IncomingSession) -> Result<()> {
            // not sure if having a different buffer for sending is correct or not...
            let mut send_buffer = vec![0; 65536].into_boxed_slice();
            let mut buffer = vec![0; 65536].into_boxed_slice();

            let session_request = session.await?;

            info!(
                "New session: Authority: '{}', Path: '{}'",
                session_request.authority(),
                session_request.path()
            );

            let connection = session_request.accept().await?;

            info!("Waiting for data from client...");

            let session_id = connection.stable_id();

            let accept_upload: AtomicBool = AtomicBool::new(false);
            loop {
                tokio::select! {
                    stream = connection.accept_bi() => {
                        signaling_stream(db_ref.clone(), stream?, &mut buffer, &connection, &accept_upload).await?;
                    }
                    uni_stream = connection.accept_uni() => {
                        if !accept_upload.load(std::sync::atomic::Ordering::Relaxed) {
                            // close and cancel if we no longer want to accept "put" requests during this session
                            uni_stream?.stop(VarInt::from_u32(101));
                        } else {
                            upload_stream(uni_stream?, &mut send_buffer, format!("{session_id}")).await?;
                        }

                    }
                }
            }
        }

        info!("Session Ended: {:?}", handle_inner(db_ref, session).await);
    }
}

// uni-directional stream from client to upload a file
async fn upload_stream(
    mut stream: RecvStream,
    buffer: &mut Box<[u8]>,
    put_folder: String,
) -> Result<()> {
    // while let Some(v) = stream.poll

    // TODO: discard file on upload fail
    let mut f = tokio::fs::File::create_new({
        let mut p = PathBuf::from(FILES_FOLDER);
        // p.push(&put_folder);
        // info!("hosting for {} in {:?}", put_folder, &p);
        // create_dir(&p).await?;
        p.push(format!("{}_nicefilename", put_folder));
        p
    })
    .await?;

    while let Some(v) = stream.read(buffer).await? {
        f.write_all(&buffer[..v]).await?;
    }

    Ok(())
}

/// a bi-directional stream used for the session for sending signals and metadata
async fn signaling_stream(
    db_ref: SqlitePool,
    mut stream: (SendStream, RecvStream),
    buffer: &mut Box<[u8]>,
    connection: &Connection,
    accept_put: &AtomicBool,
) -> Result<()> {
    info!("Accepted BI stream");

    // read bytes
    let bytes_read = match stream.1.read(buffer).await? {
        Some(bytes_read) => bytes_read,
        None => return Ok(()),
    };

    // decode
    let decoded: Result<Signal, _> = cbor4ii::serde::from_slice(&buffer[..bytes_read]);

    // allow clients to put files into the server
    accept_put.store(true, std::sync::atomic::Ordering::Relaxed);

    match decoded {
        Ok(Signal::Fetch(request)) => {
            info!("Received (bi) request from client");

            // search db for requested file hash
            let q = format!("SELECT * FROM {FILE_TABLE} WHERE Hash = $1");
            let q = sqlx::query(&q).bind(BASE64URL.encode(&request.hash));
            let record: Option<(String, i64)> = db_ref.fetch_optional(q).await?.map(|row| (row.get(1), row.get(2)));

            match record {
                Some(record) => {
                    let (filename, size) = record;
                    let path = std::env::current_dir()?.join(FILES_FOLDER).join(&filename);

                    if let Ok(file) = std::fs::read(&path) {
                        info!(
                            path = String::from(path.to_string_lossy()),
                            "Responding with file meta"
                        );

                        let mime = mime_guess::from_path(path);

                        // send the client the metadata of the file
                        send_response(
                            &mut stream.0,
                            FetchResponse::new_success(
                                request.hash,
                                filename.into(),
                                mime.first(),
                                size as u64,
                            ),
                        )
                        .await?;
                        stream.0.finish().await?;

                        // open a uni stream and shove the whole requested file down it
                        let mut uni = connection.open_uni().await?.await?;
                        debug!("Uni stream created, now sending file");
                        uni.write_all(&file).await?;
                    } else {
                        // TODO: test this case
                        error!(
                            expected_path = String::from(path.to_string_lossy()),
                            hash = BASE64URL.encode(&request.hash),
                            "File in database was not found in folder!"
                        );
                        send_response(&mut stream.0, ErrorResponse { status: 500 }).await?;
                    }
                }
                None => {
                    // hash not in db
                    debug!(
                        hash = BASE64URL.encode(&request.hash),
                        "client requested unknown hash"
                    );
                    send_response(&mut stream.0, ErrorResponse { status: 404 }).await?;
                }
            };
        }
        Err(e) => {
            info!("client sent garbled request {:?}", e);
            send_response(&mut stream.0, ErrorResponse { status: 400 }).await?;
        }
    }

    Ok(())
}

impl Drop for WebTransportServer {
    fn drop(&mut self) {
        let port = self
            .ep
            .local_addr()
            .expect("Server should already have an ip on program exit")
            .port();
        let gw = igd_next::search_gateway(Default::default())
            .expect("gateway not found, cant remove port on close");
        info!(
            "{:?}",
            gw.remove_port(igd_next::PortMappingProtocol::UDP, port)
        );
    }
}

fn logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_env_filter(env_filter)
        .init();
}

fn build_root_folder(name: &str) -> Result<PathBuf> {
    let dir = std::env::current_dir()?.join(name);
    touch_dir(&dir);
    Ok(dir)
}

fn build_internal_folder(internal_root: &PathBuf, path: &str) -> Result<PathBuf> {
    let dir = internal_root.join(path);
    touch_dir(&dir);
    Ok(dir)
}

/// create dir if it doesn't exist
/// log if folder creation failed
fn touch_dir(path: &Path) {
    match fs::read_dir(&path) {
        Ok(_) => (),
        Err(_) => {
            let _ = fs::create_dir(&path).map_err(|e| error!("{e}"));
        }
    }
}

async fn init_db(path: impl AsRef<Path>) -> anyhow::Result<SqlitePool> {
    let path = path.as_ref();
    use sqlx::prelude::*;
    use sqlx::sqlite::*;
    // create or do nothing
    let c = rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::default())?;
    c.close().map_err(|(_, e)| e)?;
    let conn = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path)).await?;
    Ok(conn)
}

#[test]
fn rust_js_cbor() -> Result<()> {
    use data_encoding::{BASE64, HEXUPPER};
    use messages::SignalRequest;

    let js_cbor_encoded = "uQABZGhhc2hYIJZms3GYoG16Z8x/2Z/3WM+6CR+R7RZSCiRdYN1QSpDe";
    let js_cbor = BASE64.decode(js_cbor_encoded.as_bytes())?;

    let rust_cbor = SignalRequest {
        hash: BASE64URL
            .decode("cbonmWDP8UdIQ0Ff0XGPwNZlGNiH-l54Gx1nvPLvUl0=".as_bytes())?
            .try_into()
            .unwrap(),
    };
    let rust_cbor = cbor4ii::serde::to_vec(Vec::new(), &rust_cbor)?;

    assert!(
        js_cbor == rust_cbor,
        "{}\n\n{}",
        HEXUPPER.encode(&js_cbor),
        HEXUPPER.encode(&rust_cbor)
    );

    Ok(())
}
