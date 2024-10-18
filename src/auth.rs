use std::fmt::format;

use data_encoding::BASE64URL;
use ed25519_dalek::{pkcs8::{EncodePrivateKey, EncodePublicKey}, SigningKey, VerifyingKey};
use rand::rngs::StdRng;
use sqlx::{prelude::*, SqlitePool};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::info;
use crate::AUTH_TABLE;

pub enum AuthCommand {
    Add(AddAuth),
    Remove(RemoveAtuhBy),
    Verify(UnverifiedKey)
}

pub struct UnverifiedKey {
    pub pubkey: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    /// callback-sorta of if the key was valid or not
    pub oneshot: tokio::sync::oneshot::Sender<bool>,
}

pub enum RemoveAtuhBy {
    Key([u8; 32]),
}

#[derive(Debug)]
pub struct AddAuth {
    pubkey: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    petname: Option<String>,
    date_added: u64,
    expires: u64,
}

impl AddAuth {

    /// SQLX bind values (Pubkey TINYTEXT, Petname TEXT, DateAdded INTEGER, Expires INTEGER)
    /// petname: None, will give an empty string
    fn sql_bind_values(self) -> (String, String, i64, i64) {
        let Self { pubkey, petname, date_added, expires } = self;
        let pubkey = BASE64URL.encode(&pubkey);
        let petname = petname.unwrap_or(format!(""));
        (
            pubkey,
            petname,
            date_added as i64,
            expires as i64,
        )
    }

    pub fn new(pubkey: impl ToString, petname: Option<String>, expires: u64) -> Result<Self, anyhow::Error> {
        let now = std::time::UNIX_EPOCH.elapsed()?.as_secs();
        let pubkey = BASE64URL.decode(pubkey.to_string().as_bytes())?.try_into().unwrap();

        Ok(Self { pubkey, petname, date_added: now, expires })
    }
}

pub struct ReservationAuthority {
    db: SqlitePool,
    rx_command: mpsc::Receiver<AuthCommand>,
}

impl ReservationAuthority {
    pub async fn new(db: SqlitePool) -> anyhow::Result<(Self, mpsc::Sender<AuthCommand>)> {
        // TODO: upload manager
        // let q = format!("CREATE TABLE IF NOT EXISTS Uploaded (Pubkey TINYTEXT, Path TEXT, Size INTEGER, Expires INTEGER)");
        // let q = sqlx::query(&q);
        // db.execute(q).await?;
        let q = format!("CREATE TABLE IF NOT EXISTS {AUTH_TABLE} (Pubkey TINYTEXT, Petname TEXT, DateAdded INTEGER, Expires INTEGER)");
        let q = sqlx::query(&q);
        db.execute(q).await?;
        
        let (tx, rx) = mpsc::channel(16);
        
        Ok((Self { db, rx_command: rx }, tx))
    }

    pub async fn start(mut self) -> anyhow::Result<()> {
        loop {
            if let Some(cmd) = self.rx_command.recv().await {
                Self::handle_command(&self.db, cmd).await?;
            } else {
                break Err(anyhow::anyhow!("Auth command channel closed unexpectedly."))
            }
        }
    }

    pub async fn handle_command(db: &SqlitePool, cmd: AuthCommand) -> anyhow::Result<()> {
        match cmd {
            AuthCommand::Add(add) => {
                info!(now_trusting =? add, "adding pubkey to trusted list");
                let (key, name, added, expires) = add.sql_bind_values();
                let q = format!("INSERT INTO {AUTH_TABLE} VALUES ($1, $2, $3, $4)");
                let q = sqlx::query(&q).bind(key).bind(name).bind(added).bind(expires);
                db.execute(q).await?;
                Ok(())
            },
            AuthCommand::Remove(RemoveAtuhBy::Key(key)) => {
                let q = format!("DELETE FROM {AUTH_TABLE} WHERE Pubkey = $1");
                let q = sqlx::query(&q).bind(BASE64URL.encode(&key));
                db.execute(q).await?;
                Ok(())
            },
            AuthCommand::Verify(unverified_key) => {
                let q = format!("SELECT * FROM {AUTH_TABLE} WHERE Pubkey = $1");
                let q = sqlx::query(&q).bind(BASE64URL.encode(&unverified_key.pubkey));
                let all = db.fetch_all(q).await?;
                if all.len() > 1 {
                    tracing::warn!("Auth table has multiple pubkeys of the same value. Something is not right.")
                }
                // silently ignore oneshot errors :)
                if let Some(row) = all.get(0) {
                    let expires: i64 = row.get(3);
                    if std::time::UNIX_EPOCH.elapsed().expect("Unix epoch was before now.").as_secs() < expires as u64 {
                        unverified_key.oneshot.send(true).ok();
                    } else {
                        tracing::warn!("key exists but expired, invalid and removed");
                        let q = format!("DELETE FROM {AUTH_TABLE} WHERE Pubkey = $1");
                        let q = sqlx::query(&q).bind(BASE64URL.encode(&unverified_key.pubkey));
                        db.execute(q).await?;
                        unverified_key.oneshot.send(false).ok();
                    }
                } else {
                    unverified_key.oneshot.send(false).ok();
                    
                }
                Ok(())
            }
        }
    }
}

#[test]
fn generate_signer_files() {
    use data_encoding::BASE64URL;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    let mut path = std::env::current_dir().unwrap();

    let mut rand = rand::rngs::OsRng;
    let secret_key = SigningKey::generate(&mut rand);
    let pub_key = secret_key.verifying_key();


    path.push("priv.pem");
    secret_key.write_pkcs8_pem_file(&path, LineEnding::CRLF).unwrap();
    println!("pubkey: {}\nprivate_key: {}", BASE64URL.encode(pub_key.as_bytes()), path.to_string_lossy());
}