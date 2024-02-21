use anyhow::Result;
use redb::{Database, ReadableTable, TableDefinition};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};

use data_encoding::BASE64URL;
use tokio::select;
use tracing::{debug, error, error_span, info, info_span, Instrument};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use wtransport::{
    endpoint::{endpoint_side::Server, IncomingSession},
    Certificate, Connection, Endpoint, RecvStream, SendStream, ServerConfig,
};

mod files;
mod messages;

use messages::{Request, Response};

use crate::{
    files::FileManager,
    messages::{send_response, ErrorResponse},
};

// TODO: DB eats up more space than it seemingly needs. maybe switch to sqlite3?

pub const FILE_DB: TableDefinition<&[u8; 32], files::FileMetaValue> =
    TableDefinition::new(&"play-wt_files");

const INTERNAL_FOLDER: &str = "wt-play_internal";
const FILES_FOLDER: &str = "wt-play_files";

#[tokio::main]
async fn main() -> Result<()> {
    logger();

    let internal_root = build_root_folder(INTERNAL_FOLDER)?;
    let fs_root = build_root_folder(FILES_FOLDER)?;

    let (_fs_watcher, fs_rx) = FileManager::new_fs_notify(&fs_root)?;

    let db_path = internal_root.join("databaseV1.db");
    let fs_manager = FileManager::new(fs_root, db_path, fs_rx)?;

    let certificate = Certificate::self_signed(&["localhost", "127.0.0.1", "::1"]);

    info!(certhash = BASE64URL.encode(certificate.hashes()[0].as_ref()),);

    let port = 4999;
    let server = WebTransportServer::new(fs_manager.db_ref(), certificate, port)?;

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
        use local_ip_address::{local_ip, local_ipv6};

        // OS gave us an ipv6 for webtransport, get our global address and print a link
        if local_addr.is_ipv6() {
            info!(
                "External IPv6 Address: https://[{}]:{}",
                local_ipv6()?,
                local_addr.port()
            )
        }

        // Attempt to add portsesu to UPnP, just in case client can only use ip4
        info!("Asking Default Gateway for UPnP port");

        let gw = search_gateway(SearchOptions::default())?;

        // local ip4 (just incase our webtransport ip is v6)
        let local_ip4 = SocketAddr::new(local_ip()?, local_addr.port());

        debug!("Adding UPnP port with ip4 {}", local_ip4);
        gw.add_port(
            PortMappingProtocol::UDP,
            local_addr.port(),
            local_ip4,
            WEEK_DUR,
            "play-wt",
        )?;
        info!(
            "External Address: https://{}:{}",
            gw.get_external_ip()?,
            local_addr.port()
        );

        Ok(())
    }
    let span = error_span!("Net Startup");
    let _enter = span.enter();
    let _ = inner(local_addr).map_err(|e| error!("{e}"));
    info!("Finished!");

    Ok(())
}

pub struct WebTransportServer {
    ep: Endpoint<Server>,
    db: Arc<Database>,
}

impl WebTransportServer {
    fn new(db: Arc<Database>, cert: Certificate, port: u16) -> Result<Self> {
        let config = ServerConfig::builder()
            .with_bind_config(wtransport::config::IpBindConfig::InAddrAnyDual, port)
            .with_certificate(cert)
            .keep_alive_interval(Some(Duration::from_secs(3)))
            .build();

        let connection = Endpoint::server(config)?;

        Ok(Self { db, ep: connection })
    }

    pub async fn serve(self) -> Result<()> {
        let _ = upnp(self.ep.local_addr()?).await.map_err(|e| error!("{e}"));

        for id in 0.. {
            let incoming_session = self.ep.accept().await;

            tokio::spawn(
                Self::handle_incoming_session(self.db.clone(), incoming_session)
                    .instrument(info_span!("Connection", id)),
            );
        }

        Ok(())
    }

    async fn handle_incoming_session(db_ref: Arc<Database>, session: IncomingSession) {
        async fn handle_inner(db_ref: Arc<Database>, session: IncomingSession) -> Result<()> {
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
                        signaling_stream(db_ref.clone(), stream?, &mut buffer, &connection).await?;
                    }
                    // dgram = connection.receive_datagram() => {
                    //     let dgram = dgram?;
                    //     let str_data = std::str::from_utf8(&dgram)?;

                    //     info!("Received (dgram) '{str_data}' from client");

                    //     connection.send_datagram(b"ACK")?;
                    // }
                }
            }
        }

        info!("Session Ended: {:?}", handle_inner(db_ref, session).await);
    }
}

async fn signaling_stream(
    db_ref: Arc<Database>,
    mut stream: (SendStream, RecvStream),
    buffer: &mut Box<[u8]>,
    connection: &Connection,
) -> Result<()> {
    info!("Accepted BI stream");

    // read bytes
    let bytes_read = match stream.1.read(buffer).await? {
        Some(bytes_read) => bytes_read,
        None => return Ok(()),
    };

    // decode
    let decoded: Result<Request, _> = cbor4ii::serde::from_slice(&buffer[..bytes_read]);

    match decoded {
        Ok(request) => {
            info!("Received (bi) request from client");

            // search db for requested file hash
            let read_tx = db_ref.begin_read()?;
            let table = read_tx.open_table(FILE_DB)?;
            let record = table.get(&request.hash)?;

            match record {
                Some(record) => {
                    let (size, filename) = record.value();
                    let path = std::env::current_dir()?.join(FILES_FOLDER).join(filename);

                    if let Ok(file) = std::fs::read(&path) {
                        info!(
                            path = String::from(path.to_string_lossy()),
                            "Responding with file meta"
                        );

                        let mime = mime_guess::from_path(path);

                        send_response(
                            &mut stream.0,
                            Response::new_success(
                                request.hash,
                                filename.into(),
                                mime.first(),
                                size,
                            ),
                        )
                        .await?;
                        stream.0.finish().await?;

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

#[test]
fn rust_js_cbor() -> Result<()> {
    use data_encoding::{BASE64, HEXUPPER};
    use messages::Request;

    let js_cbor_encoded = "uQABZGhhc2hYIJZms3GYoG16Z8x/2Z/3WM+6CR+R7RZSCiRdYN1QSpDe";
    let js_cbor = BASE64.decode(js_cbor_encoded.as_bytes())?;

    let rust_cbor = Request {
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
