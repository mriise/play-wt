use std::ops::{Add, Div, Mul, Sub};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::SystemTime;

use crate::{error, ActiveServerConfig};

use time::format_description::modifier::UnixTimestamp;
use time::{Duration, OffsetDateTime};
use tokio::select;
use tracing::{debug, info, info_span};
use wtransport::endpoint::endpoint_side::Server;
use wtransport::tls::error::InvalidSan;
use wtransport::tls::{Certificate, CertificateChain, PrivateKey};
use wtransport::{Endpoint, Identity, ServerConfig};

use tokio_cron_scheduler::JobScheduler;

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

#[derive(Debug)]
struct RollingCert {
    cert: Identity,
    week_index: WeekIndex,
}

impl RollingCert {
    // yay no serde! /s
    /// serialize to [2 bytes week index, 32 bytes hash of cert]
    fn serialize(&self) -> Vec<u8> {
        let index_b = self.week_index.0.to_le_bytes();
        // all rolling certs for this server are self signed, we only need the frist
        let cert = &self.cert.certificate_chain().as_ref()[0];
        let cert_b = *cert.hash().as_ref();
        [index_b.as_slice(), cert_b.as_slice()].concat()
    }

    fn new<I, S>(subject_alt_names: I, not_before: OffsetDateTime) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self {
            cert: new_cert(subject_alt_names, not_before)?,
            week_index: not_before.into(),
        })
    }

    fn next_mint_date(&self) -> OffsetDateTime {
        self.week_index.next_index().date_offset()
    }
}

/// week index starts on sunday at midnight of the current week, such that the index of the current time will give us the cert that was made for this week
#[derive(Debug, Clone)]
struct WeekIndex(u16);
const UNIX_WEEK: i64 = 604_800;
const UNIX_UTC_OFFSET: i64 = 345_600;

impl WeekIndex {
    // sunday at midnight of last week so when we have make certs they overlapping for 7 days and valid for this week
    fn date_offset(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp((self.0 as i64).mul(UNIX_WEEK).add(UNIX_UTC_OFFSET)).unwrap()
    }

    fn hot_mint_date(now: OffsetDateTime) -> Self {
        now.sub(Duration::days(7)).into()
    }
    fn stale_mint_date(now: OffsetDateTime) -> Self {
        now.sub(Duration::days(14)).into()
    }
    fn next_index(&self) -> Self {
        Self(self.0 + 1).into()
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
        println!("{:?}\n\tnext {}\n\thot {}\n\tstale {}", index, index.date_offset(), WeekIndex::hot_mint_date(day).date_offset(), WeekIndex::stale_mint_date(day).date_offset());
    }
    println!("epoch index {:?}", WeekIndex::from(OffsetDateTime::UNIX_EPOCH))
}

pub struct CertManager {
    hot_cert: RollingCert,
    stale_cert: RollingCert,
    tickrate: Duration,
    ep: Arc<Endpoint<Server>>,
    start_config: ActiveServerConfig
}

impl CertManager {
    pub fn new(ep: Arc<Endpoint<Server>>, start_config: ActiveServerConfig) -> anyhow::Result<Self> {
        
        let inital_now = time::OffsetDateTime::now_utc();

        let hot_cert = RollingCert::new(["localhost"], WeekIndex::hot_mint_date(inital_now).date_offset())?;
        let stale_cert = RollingCert::new(["localhost"], WeekIndex::stale_mint_date(inital_now).date_offset())?;

        Ok(Self { hot_cert , stale_cert, tickrate: Duration::minutes(30), ep, start_config })
    }

    /// make new certs every 7 days, such that there will always be 2 valid certs
    pub async fn start(&mut self) -> anyhow::Result<()> {        
        let span = info_span!("Cert Manager");

        let mut debug_timeskip = 0;
        // tick every min
        loop {
            let _enter = span.enter();
            
            let now = time::OffsetDateTime::now_utc();

            // REMOVEME
            let now = now.add(Duration::hours(debug_timeskip));
            debug!("TICK. time till new cert {:#}", self.stale_cert.next_mint_date()-now);

            // make a new cert and push out stale
            if now >= self.stale_cert.next_mint_date() {
                // swap because we cant deref either safely
                std::mem::swap(&mut self.stale_cert, &mut self.hot_cert);
                self.hot_cert = RollingCert::new(["localhost"], self.hot_cert.next_mint_date())?;

                info!(hot_cert=?self.hot_cert, stale_cert=?self.stale_cert, "creating new certs and reloading");


                // TODO: rebind & hot config reload
                // use the new stale cert
                let new_config = ServerConfig::builder()
                    .with_bind_default(self.start_config.port)
                    .with_identity(&self.stale_cert.cert)
                    .keep_alive_interval(self.start_config.keepalive)
                    .build();
                self.ep.reload_config(new_config, false)?;
            }
            // TODO save certs to files!
            
            //REMOVEME
            // debug_timeskip+= 12;
            tokio::time::sleep(self.tickrate.try_into()?).await;
        }
    }


    pub fn startup_load_ident() -> anyhow::Result<Identity> {
        let identity = Identity::self_signed(&["localhost", "127.0.0.1", "::1"])?;
        // TODO load from files actually
        Ok(identity)
    }
}

