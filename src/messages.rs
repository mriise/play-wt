use mime_guess::Mime;
use serde::{Deserialize, Serialize};
use wtransport::SendStream;

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    #[serde(with = "serde_bytes")]
    pub hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    status: u32,

    filename: String,
    /// Empty String means we dont know!
    mime: String,

	#[serde(with = "serde_bytes")]
    pub hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: u32,
}

impl Response {
    pub fn new_success(hash: [u8; 32], filename: String, mime: Option<Mime>) -> Self {
        Self {
            status: 200,
			hash,
            filename,
            mime: mime.map(|m| m.essence_str().into()).unwrap_or_default(),
        }
    }
}

pub async fn send_response(stream: &mut SendStream, message: impl Serialize) -> anyhow::Result<()> {
    let message = cbor4ii::serde::to_vec(Vec::new(), &message)?;
    stream.write_all(&message).await?;
    Ok(())
}
