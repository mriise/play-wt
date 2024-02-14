use wtransport::{Certificate, Endpoint, ServerConfig};
use data_encoding::BASE64;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {


    let certificate = Certificate::self_signed(&["localhost", "127.0.0.1", "::1"]);

    println!("self signed certhash: {}", BASE64.encode(certificate.hashes()[0].as_ref()));

    let config = ServerConfig::builder()
        .with_bind_config(wtransport::config::IpBindConfig::LocalV4, 4433)
        .with_certificate(certificate)
        .build();

    let connection = Endpoint::server(config)?;

    println!("listening for WebTransport connection at {}", connection.local_addr()?);

    
    loop {

        let connection = connection
            .accept()
            .await     // Awaits connection
            .await;    // Awaits session request

        let connection = match connection {
            Ok(ok) => ok.accept().await,
            Err(e) => {
                Err(e)
            }
        };
        let stream = match connection {
            Ok(connection) => Some(connection.accept_bi().await?),
            Err(e) => {
                println!("{e}");
                None
            }
        };

        // TODO: actually do ping pong with the stream

        stream.map(|stream| println!("connection accepted {:?}", stream));
    }
}