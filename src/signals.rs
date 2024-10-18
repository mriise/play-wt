use mime_guess::Mime;
use serde::{Deserialize, Serialize};
use wtransport::SendStream;


#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Signal {
    Fetch(FetchRequest),
    Put(PutRequest),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FetchRequest {
    #[serde(with = "serde_bytes")]
    pub hash: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PutRequest {
    auth: SignedAuthToken,

    filename: String,
    /// Empty String means we dont know!
    mime: String,

    size: u64,
}

#[derive(Serialize, Deserialize, Debug)]
// TODO: not this, likely insecure.
pub struct SignedAuthToken {
    /// ed25519 pubkey of the issuer
    #[serde(with = "serde_bytes")]
    issuer: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    /// signautre of `token` bytes
    #[serde(with = "serde_bytes")]
    signature: [u8; ed25519_dalek::SIGNATURE_LENGTH],
    /// DAG-CBOR serialized [AuthToken]
    #[serde(with = "serde_bytes")]
    token: Vec<u8>,
}

impl SignedAuthToken {
    fn verify(&self) -> bool {
        let sig = ed25519_dalek::Signature::from_bytes(&self.signature);
        ed25519_dalek::VerifyingKey::from_bytes(&self.issuer)
            .and_then(|key| key.verify_strict(&self.token, &sig))
            .is_ok()
    }

    fn read_token(&self) -> Option<AuthToken> {
        let token: AuthToken = cbor4ii::serde::from_slice(&self.token).ok()?;
        Some(token)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthToken {
    /// unix timestamp that this token (and the file uploaded on behalf of it) expires
    expires: u64,
    /// max size in bytes
    max_size: u64,
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
