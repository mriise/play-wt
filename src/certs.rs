use std::fmt::{format, Debug};
use std::fs::read_dir;
use std::ops::{Add, Div, Mul, Sub};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::SystemTime;

use crate::{error, ActiveServerConfig};

use serde::{Deserialize, Serialize};
use time::format_description::modifier::UnixTimestamp;
use time::{Duration, OffsetDateTime};
use tokio::fs::remove_file;
// use tokio::fs::read_dir;
use tokio::select;
use tracing::{debug, debug_span, info, info_span, trace, warn};
use wtransport::endpoint::endpoint_side::Server;
use wtransport::tls::error::InvalidSan;
use wtransport::tls::{Certificate, CertificateChain, PrivateKey};
use wtransport::{Endpoint, Identity, ServerConfig};

/// create a new self-signed cert that is valid begining at `not_before` and expires 14 days after
pub fn new_cert<I, S>(
    subject_alt_names: I,
    not_before: OffsetDateTime,
) -> Result<Identity, InvalidSan>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    use rcgen::CertificateParams;
    use rcgen::DistinguishedName;
    use rcgen::DnType;
    use rcgen::KeyPair;
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use time::Duration;

    let subject_alt_names = subject_alt_names
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect::<Vec<_>>();

    let mut dname = DistinguishedName::new();
    dname.push(DnType::CommonName, "wtransport self-signed");

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .expect("algorithm for key pair is supported");

    let mut cert_params = CertificateParams::new(subject_alt_names).map_err(|_| InvalidSan)?;
    cert_params.distinguished_name = dname;
    cert_params.not_before = not_before;
    cert_params.not_after = not_before
        .checked_add(Duration::days(14))
        .expect("addition does not overflow");

    let cert = cert_params
        .self_signed(&key_pair)
        .expect("inner params are valid");

    Ok(Identity::new(
        // TODO: unwrap :)
        CertificateChain::single(Certificate::from_der(cert.der().clone().to_vec()).unwrap()),
        PrivateKey::from_der_pkcs8(key_pair.serialize_der()),
    ))
}

pub struct RollingCert {
    identity: Identity,
    week_index: WeekIndex,
}

impl Debug for RollingCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RollingCert")
            .field("week_index", &self.week_index.int())
            .field("certhash", &self.certhash_base64url())
            .field("mint_date", &self.week_index.date_offset())
            .finish()
    }
}

impl RollingCert {
    // yay no serde! /s
    /// serialize to [2 bytes week index, 32 bytes hash of cert]
    fn serialize(&self) -> Vec<u8> {
        let index_b = self.week_index.0.to_le_bytes();
        // all rolling certs for this server are self signed, we only need the frist
        let cert = &self.identity.certificate_chain().as_ref()[0];
        let cert_b = *cert.hash().as_ref();
        [index_b.as_slice(), cert_b.as_slice()].concat()
    }

    async fn new<I, S>(
        subject_alt_names: I,
        not_before: WeekIndex,
        flush_path: Option<&PathBuf>,
    ) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let new = Self {
            identity: new_cert(subject_alt_names, not_before.date_offset())?,
            week_index: not_before,
        };
        debug!(new_cert =? new);
        if let Some(cert_path) = flush_path {
            let mut csv_path = cert_path.clone();
            csv_path.push(crate::INTERNAL_CERT_HISTORY_TABLE);

            if csv_path.exists() {
                let mut rdr = csv::Reader::from_path(&csv_path)?;
                let mut iter = rdr.deserialize();
                // linear search go brrrr
                while let Some(Ok(record)) = iter.next() {
                    let record: CertRecord = record;
                    if new.week_index.int() == record.week_index {
                        // exists, load instead
                        let (cert_path, key_path) = new.week_index.index_cert_key_files(&cert_path);
                        debug!(cert_path =? cert_path, key_path =? key_path, "found valid stale record");
                        let new = RollingCert::load(&cert_path, &key_path, new.week_index).await?;
                        return Ok(new);
                    }
                }
            }

            new.flush_files(cert_path).await?;

            // TODO erase files or do some cleanup before just exiting
            new.flush_to_csv(&csv_path)?;
        }
        Ok(new)
    }

    fn next_mint_date(&self) -> OffsetDateTime {
        self.week_index.next_index().date_offset()
    }

    pub fn certhash_base64url(&self) -> String {
        use data_encoding::BASE64URL;
        let cert = &self.identity.certificate_chain().as_ref()[0];
        BASE64URL.encode(cert.hash().as_ref())
    }

    pub async fn load(
        cert_path: &PathBuf,
        key_path: &PathBuf,
        week_index: WeekIndex,
    ) -> anyhow::Result<Self> {
        let cert = Identity::load_pemfiles(cert_path, key_path).await?;
        Ok(Self {
            identity: cert,
            week_index,
        })
    }

    /// assumes csv already exists.
    fn flush_to_csv(&self, csv_path: &PathBuf) -> anyhow::Result<()> {
        let mut buffer = Vec::new();
        if csv_path.exists() {
            // see if this cert is already in there, certhash is valid enough of a unique key
            let to_flush_certhash = self.certhash_base64url();

            let mut rdr = csv::Reader::from_path(&csv_path)?;
            let mut iter = rdr.deserialize();
            // linear search go brrrr
            while let Some(Ok(record)) = iter.next() {
                let record: CertRecord = record;
                if to_flush_certhash == record.certhash_base64 {
                    // exists, do nothing
                    return Ok(());
                }
                buffer.push(record);
            }
        }

        debug!(week_index =? self.week_index.0, certhash = self.certhash_base64url(), "adding identity to cert log");

        let mut wtr = csv::Writer::from_path(&csv_path)?;
        wtr.serialize(CertRecord {
            week_index: self.week_index.0,
            certhash_base64: self.certhash_base64url(),
            mint_date: self.week_index.date_offset().to_string(),
        })?;

        for item in buffer {
            trace!("adding back in record to csv: {item:?}");
            wtr.serialize(item)?;
        }

        wtr.flush()?;

        Ok(())
    }

    async fn flush_files(&self, cert_path: &PathBuf) -> anyhow::Result<()> {
        let (cert_path, key_path) = self.week_index.index_cert_key_files(&cert_path);
        debug!(cert_path =? cert_path, key_path =? key_path, "flushing identity to files");
        if cert_path.exists() || key_path.exists() {
            return Err(anyhow::anyhow!(
                "Cert or Key files for week index {} exist, please remove",
                self.week_index.0
            ));
        }
        // TODO catch error and remove any half written files
        self.identity
            .certificate_chain()
            .store_pemfile(cert_path)
            .await?;
        self.identity
            .private_key()
            .store_secret_pemfile(key_path)
            .await?;
        Ok(())
    }
}

/// week index starts on sunday at midnight of the current week, such that the index of the current time will give us the cert that was made for this week
/// TODO: this description is like partially against implementation at least, i have not the brain effort to re-think what _exactly_ the implementation is doing 
///     compared to what i planned for it to do.
#[derive(Debug, Clone, Copy)]
pub struct WeekIndex(u16);
const UNIX_WEEK: i64 = 604_800;
const UNIX_UTC_OFFSET: i64 = 345_600;

impl WeekIndex {
    /// sunday at midnight of last week so when we have make certs they overlapping for 7 days and valid for this week
    fn date_offset(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp((self.0 as i64).mul(UNIX_WEEK).add(UNIX_UTC_OFFSET))
            .unwrap()
    }

    // TODO: remove this because i really dont feel safe messing with days when we should be able to find this using previous index
    fn hot_mint_index(now: OffsetDateTime) -> Self {
        now.sub(Duration::days(7)).into()
    }
    fn stale_mint_index(now: OffsetDateTime) -> Self {
        now.sub(Duration::days(14)).into()
    }
    fn next_index(&self) -> Self {
        Self(self.0 + 1).into()
    }
    fn previous_index(&self) -> Self {
        Self(self.0 - 1).into()
    }

    fn int(&self) -> u16 {
        self.0
    }

    /// given a folder return the expected cert and key file paths for this week index
    /// (cert, key)
    fn index_cert_key_files(&self, root_path: &PathBuf) -> (PathBuf, PathBuf) {
        let mut cert_path = root_path.clone();
        cert_path.push(format!("{}{}", self.0, CertManager::CERT_SUFFIX));
        let mut key_path = root_path.clone();
        key_path.push(format!("{}{}", self.0, CertManager::KEY_SUFFIX));
        (cert_path, key_path)
    }
}

impl From<OffsetDateTime> for WeekIndex {
    fn from(value: OffsetDateTime) -> Self {
        let unix_ts = value.unix_timestamp();
        // https://stackoverflow.com/a/64293860
        Self((unix_ts.add(UNIX_UTC_OFFSET).div(UNIX_WEEK)) as u16)
    }
}

#[test]
fn week_index() {
    let now = time::OffsetDateTime::now_utc();

    for day in 0..32 {
        let day = now.checked_add(Duration::days(day)).unwrap();
        let index = WeekIndex::from(day);
        println!(
            "{:?}\n\tnext {}\n\thot {}\n\tstale {}",
            index,
            index.date_offset(),
            WeekIndex::hot_mint_index(day).date_offset(),
            WeekIndex::stale_mint_index(day).date_offset()
        );
    }
    println!(
        "epoch index {:?}",
        WeekIndex::from(OffsetDateTime::UNIX_EPOCH)
    )
}

pub struct CertManager {
    hot_cert: RollingCert,
    stale_cert: RollingCert,
    tickrate: Duration,
    ep: Option<Arc<Endpoint<Server>>>,
    start_config: ActiveServerConfig,
}

impl CertManager {
    const KEY_SUFFIX: &str = "_key.pem";
    const CERT_SUFFIX: &str = "_cert.pem";

    pub async fn new(start_config: ActiveServerConfig) -> anyhow::Result<Self> {
        let inital_now = time::OffsetDateTime::now_utc();

        let span = debug_span!("CertManager Startup");
        let _entered = span.enter();
        debug!("loading certs from files");
        let (stale_cert, hot_cert) = Self::load_certs(inital_now, &start_config).await.unwrap();
        // .unwrap_or(Self::generate_fresh(inital_now, &start_config).await?);
        Ok(Self {
            hot_cert,
            stale_cert,
            tickrate: Duration::minutes(30),
            // tickrate: Duration::milliseconds(100),
            ep: None,
            start_config,
        })
    }

    // async fn generate_fresh(
    //     date: OffsetDateTime,
    //     start_config: &ActiveServerConfig,
    // ) -> anyhow::Result<(RollingCert, RollingCert)> {

    //     let hot_cert = RollingCert::new(
    //         &start_config.subject_alt_names,
    //         WeekIndex::hot_mint_index(date).date_offset(),
    //         Some(&start_config.cert_root),
    //     )
    //     .await?;
    //     let stale_cert = RollingCert::new(
    //         &start_config.subject_alt_names,
    //         WeekIndex::stale_mint_index(date).date_offset(),
    //         Some(&start_config.cert_root),
    //     )
    //     .await?;
    //     Ok((hot_cert, stale_cert))
    // }

    /// make new certs every 7 days, such that there will always be 2 valid certs
    /// always run on the current stale, hold hot in buffer, and only generate next cert until stale expires
    pub async fn start(&mut self, ep: Arc<Endpoint<Server>>) -> anyhow::Result<()> {
        self.ep = Some(ep);
        let d_span = debug_span!("Cert Manager");

        // initial reload
        let new_config = ServerConfig::builder()
            .with_bind_default(self.start_config.port)
            .with_identity(&self.stale_cert.identity)
            .keep_alive_interval(self.start_config.keepalive)
            .build();
        debug!(hot_cert=?self.hot_cert, stale_cert=?self.stale_cert, "Reloading with initial certs.");
        info!(passkey=self.client_passkey(), "Initial client Passkey.");
        // if let is unfortunately needed, we know from the function call that this is always Some.
        if let Some(ep) = &self.ep {
            ep.reload_config(new_config, false)?
        }

        let mut debug_timeskip = 0;
        // tick every min
        loop {
            let _enter = d_span.enter();

            let now = time::OffsetDateTime::now_utc();

            // REMOVEME
            let now = now.add(Duration::hours(debug_timeskip));
            debug!(
                "TICK. time till new cert {:#}",
                self.stale_cert.next_mint_date() - now
            );

            // make a new cert and push out stale
            if now >= self.stale_cert.next_mint_date() {
                let expired_week_index = self.stale_cert.week_index;

                // swap because we cant deref either safely
                std::mem::swap(&mut self.stale_cert, &mut self.hot_cert);
                self.hot_cert = RollingCert::new(
                    &self.start_config.subject_alt_names,
                    self.stale_cert.week_index.next_index(),
                    Some(&self.start_config.cert_root),
                )
                .await?;

                debug_assert!(self.hot_cert.week_index.int() == self.stale_cert.week_index.int() + 1);
                debug!(hot_cert=?self.hot_cert, stale_cert=?self.stale_cert, "creating new certs and reloading");
                info!(passkey=self.client_passkey(), "Client Passkey updated.");
                
                // TODO: rebind & hot config reload
                // use the new stale cert
                let new_config = ServerConfig::builder()
                    .with_bind_default(self.start_config.port)
                    .with_identity(&self.stale_cert.identity)
                    .keep_alive_interval(self.start_config.keepalive)
                    .build();
                // if let is unfortunately needed, we know from the function call that this is always Some.
                if let Some(ep) = &self.ep {
                    ep.reload_config(new_config, false)?
                }

                let (cert_path, key_path) =  expired_week_index.index_cert_key_files(&self.start_config.cert_root);
                debug!("cleaning up old cert and key {cert_path:?}   {key_path:?}");
                // TODO another thread for this one please thankyhohu
                remove_file(cert_path).await?;
                remove_file(key_path).await?;
            }

            //REMOVEME
            // debug_timeskip += 1;
            tokio::time::sleep(self.tickrate.try_into()?).await;
        }
    }

    /// load certs from internal cert folder with naming following `<week_index>_cert.pem`&`<week_index>_key.pem` (not exact but for our purposed good enough)
    /// `(stale, hot)`
    pub async fn load_certs(
        now: OffsetDateTime,
        config: &ActiveServerConfig,
    ) -> anyhow::Result<(RollingCert, RollingCert)> {
        let hot_index = WeekIndex::hot_mint_index(now).next_index();
        let stale_index = hot_index.previous_index();
        debug_assert!(hot_index.int() > stale_index.int());
        debug!(hot_index =? hot_index, stale_index =? stale_index, "loading certs for hot and stale indexes");
        // (stale, hot)
        let mut certs = (None, None);

        let mut csv_path = config.cert_root.clone();
        csv_path.push(crate::INTERNAL_CERT_HISTORY_TABLE);

        // read our history file to see if we had it
        if csv_path.exists() {
            // see if this cert is already in there, certhash is valid enough of a unique key
            let mut rdr = csv::Reader::from_path(&csv_path)?;
            let mut iter = rdr.deserialize();
            // linear search go brrrr
            while let Some(Ok(record)) = iter.next() {
                let record: CertRecord = record;
                trace!(record =? record);
                // if we read something in the history but its not there, error out, user issue! :)
                // TODO, simply overwirte with a new cert if we are missing files
                // certs are temporary, code is forever!
                if record.week_index == hot_index.0 {
                    let (cert_path, key_path) = hot_index.index_cert_key_files(&config.cert_root);
                    debug!(cert_path =? cert_path, key_path =? key_path, "found valid hot record");

                    let hot_cert = RollingCert::load(&cert_path, &key_path, hot_index).await?;
                    certs.1 = Some(hot_cert);
                } else if record.week_index == stale_index.0 {
                    let (cert_path, key_path) = stale_index.index_cert_key_files(&config.cert_root);
                    debug!(cert_path =? cert_path, key_path =? key_path, "found valid stale record");
                    let stale_cert = RollingCert::load(&cert_path, &key_path, stale_index).await?;
                    certs.0 = Some(stale_cert);
                }
            }
        }
        debug!("loaded certs, {:?}", certs);

        // fill in missing
        let out: (RollingCert, RollingCert) = match certs {
            // loaded both, do nothing
            (Some(stale), Some(hot)) => (stale, hot),
            // everything else make another serialize and write to history
            (None, Some(hot)) => (
                RollingCert::new(
                    &config.subject_alt_names,
                    stale_index,
                    Some(&config.cert_root),
                )
                .await?,
                hot,
            ),
            (Some(stale), None) => (
                stale,
                RollingCert::new(
                    &config.subject_alt_names,
                    hot_index,
                    Some(&config.cert_root),
                )
                .await?,
            ),
            (None, None) => (
                RollingCert::new(
                    &config.subject_alt_names,
                    stale_index,
                    Some(&config.cert_root),
                )
                .await?,
                RollingCert::new(
                    &config.subject_alt_names,
                    hot_index,
                    Some(&config.cert_root),
                )
                .await?,
            ),
        };
        Ok(out)
    }

    /// base64url encode raw bytes of week index and cert hash in order of (stale, hot) 
    /// e.g. `[stale_index: u16, stale_hash: [u8; 32], hot_index: u16, hot_hash: [u8; 32]]`
    /// this gives the client a `4>n>2` week window to access this server
    fn client_passkey(&self) -> String {
        data_encoding::BASE64URL.encode(&[self.stale_cert.serialize(), self.hot_cert.serialize()].concat())
    }
}

// #[tokio::test]
// async fn csv_test() {
//     let mut dir = std::env::current_dir().unwrap();
//     dir.push("test.csv");
//     let (cert, _) = CertManager::generate_fresh(OffsetDateTime::now_utc(), &ActiveServerConfig { port: 0, keepalive: None, cert_root: dir, subject_alt_names: vec![format!("localhost")] }).await.unwrap();
//     // CertManager::flush_cert_csv(&dir, &cert, false).unwrap();
// }

#[derive(Debug, Serialize, Deserialize)]
struct CertRecord {
    week_index: u16,
    certhash_base64: String,
    mint_date: String,
}
