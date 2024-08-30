use mime_guess::Mime;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use wtransport::SendStream;

#[derive(Serialize, Deserialize, Debug)]
pub struct SignalRequest {
    #[serde(with = "serde_bytes")]
    pub hash: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Signal {
    Fetch(SignalRequest),
    // Put()
}

#[derive(Serialize, Deserialize)]
pub struct FetchResponse {
    status: u32,

    filename: String,
    /// Empty String means we dont know!
    mime: String,

    size: u64,

    #[serde(with = "serde_bytes")]
    hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: u32,
}

impl FetchResponse {
    pub fn new_success(hash: [u8; 32], filename: String, mime: Option<Mime>, size: u64) -> Self {
        Self {
            status: 200,
            hash,
            filename,
            mime: mime.map(|m| m.essence_str().into()).unwrap_or_default(),
            size,
        }
    }
}

pub async fn send_response(stream: &mut SendStream, message: impl Serialize) -> anyhow::Result<()> {
    let message = cbor4ii::serde::to_vec(Vec::new(), &message)?;
    stream.write_all(&message).await?;
    Ok(())
}
