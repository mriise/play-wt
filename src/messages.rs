use serde::{Deserialize, Serialize};
use wtransport::SendStream;

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    #[serde(with = "serde_bytes")]
    pub hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub status: u32,
    // TODO: Option instead of depending on how cbor4ii encodes and cbor-x decodes it
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,

	pub filename: String,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: u32,
}

impl Response {
    pub fn new_success(data: Vec<u8>, filename: String) -> Self {
        Self { status: 200, data, filename }
    }
}

pub async fn send_response(stream: &mut SendStream, message: impl Serialize) -> anyhow::Result<()> {
    let message = cbor4ii::serde::to_vec(Vec::new(), &message)?;
    stream.write_all(&message).await?;
    Ok(())
}
