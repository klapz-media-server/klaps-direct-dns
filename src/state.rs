//! State shared between the API and the DNS server.
//!
//! Disk is the source of truth (one `.bin` per hash). In front of it sits a RAM cache
//! bounded in bytes (50 MB by default): moka evicts based on usage (TinyLFU: frequency +
//! recency), so the most requested hashes stay in memory. Missing hashes are cached too
//! (empty entry, a few bytes) so DNS queries for bogus names don't hit the disk every time.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::Bytes;
use moka::future::Cache;
use tokio::sync::{Mutex, OnceCell};
use tracing::{info, warn};

use crate::acme;
use crate::cloudflare::Cloudflare;
use crate::hash::Hasher;
use crate::store::{CertData, Record, Store};

pub struct Config {
    /// Lowercase, no trailing dot, e.g. "klapz.direct".
    pub base_domain: String,
    pub wildcard: bool,
    pub directory_url: String,
    pub email: Option<String>,
    pub data_dir: PathBuf,
    pub renew_before: Duration,
    pub propagation_delay: Duration,
    pub cache_max_bytes: u64,
    /// Exact number of characters a token must have.
    pub token_length: usize,
}

/// What we keep in memory for a hash. The certificate JSON response is serialized once,
/// then served as-is (cloning a `Bytes` is just a refcount bump).
pub struct Entry {
    pub record: Record,
    pub cert_json: Option<Bytes>,
}

impl Entry {
    /// Approximate RAM footprint, for the cache size limit.
    fn weight(&self, key: &str) -> u32 {
        const OVERHEAD: usize = 256; // cache internals, Arc, Vec...
        let txt: usize = self.record.txt.iter().map(|t| t.len() + 24).sum();
        let cert = self.record.cert.as_ref().map_or(0, |c| c.chain.len() + c.key.len());
        let json = self.cert_json.as_ref().map_or(0, Bytes::len);
        (OVERHEAD + key.len() + txt + cert + json).min(u32::MAX as usize) as u32
    }
}

pub struct AppState {
    pub cfg: Config,
    pub hasher: Hasher,
    store: Store,
    cloudflare: Option<Cloudflare>,
    cache: Cache<String, Arc<Entry>>,
    /// One lock per in-flight issuance: two concurrent requests for the same token only
    /// trigger a single Let's Encrypt order. Removed once the issuance completes.
    issuing: Cache<String, Arc<Mutex<()>>>,
    /// Hashes whose refresh recently failed: no new attempt for an hour, the still-valid
    /// certificate is served instead (avoids burning Let's Encrypt quotas in a loop).
    refresh_backoff: Cache<String, ()>,
    account: OnceCell<instant_acme::Account>,
}

const REFRESH_BACKOFF: Duration = Duration::from_secs(3_600);

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

impl AppState {
    pub fn new(cfg: Config, hasher: Hasher, cloudflare: Option<Cloudflare>) -> Self {
        let cache = Cache::builder()
            .max_capacity(cfg.cache_max_bytes)
            .weigher(|k: &String, v: &Arc<Entry>| v.weight(k))
            .build();
        info!("RAM cache: {} MB max", cfg.cache_max_bytes / 1_000_000);
        Self {
            store: Store::new(cfg.data_dir.join("certs")),
            cfg,
            hasher,
            cloudflare,
            cache,
            issuing: Cache::builder().time_to_idle(Duration::from_secs(600)).build(),
            refresh_backoff: Cache::builder().time_to_live(REFRESH_BACKOFF).build(),
            account: OnceCell::new(),
        }
    }

    pub fn domain(&self, hash: &str) -> String {
        format!("{hash}.{}", self.cfg.base_domain)
    }

    pub fn names(&self, hash: &str) -> Vec<String> {
        let domain = self.domain(hash);
        if self.cfg.wildcard {
            vec![format!("*.{domain}"), domain]
        } else {
            vec![domain]
        }
    }

    fn build_entry(&self, hash: &str, record: Record) -> Arc<Entry> {
        let cert_json = record.cert.as_ref().map(|c| {
            let body = serde_json::json!({
                "hash": hash,
                "domain": self.domain(hash),
                "names": self.names(hash),
                "not_after": c.not_after,
                "certificate": c.chain,
                "private_key": c.key,
            });
            Bytes::from(serde_json::to_vec(&body).expect("JSON is always serializable"))
        });
        Arc::new(Entry { record, cert_json })
    }

    /// Entry for an (already validated) hash: from RAM, otherwise from disk.
    /// If several requests miss the cache at once, only one reads the disk.
    pub async fn get(&self, hash: &str) -> Result<Arc<Entry>> {
        self.cache
            .try_get_with_by_ref(hash, async {
                let record = self.store.get(hash).await?.unwrap_or_default();
                Ok::<_, anyhow::Error>(self.build_entry(hash, record))
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e:#}"))
    }

    /// For a DNS frontend: `_acme-challenge.<hash>.<base_domain>` -> entry (read `record.txt`).
    /// Case-insensitive, accepts a trailing dot.
    #[allow(dead_code)] // handy for another DNS frontend; dns.rs resolves names itself
    pub async fn txt_for_name(&self, qname: &str) -> Option<Arc<Entry>> {
        let qname = qname.strip_suffix('.').unwrap_or(qname);
        let lower;
        let qname = if qname.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = qname.to_ascii_lowercase();
            lower.as_str()
        } else {
            qname
        };
        let rest = qname.strip_prefix("_acme-challenge.")?;
        let hash = rest.strip_suffix(self.cfg.base_domain.as_str())?.strip_suffix('.')?;
        if !self.hasher.is_valid(hash) {
            return None;
        }
        self.get(hash).await.ok().filter(|e| !e.record.txt.is_empty())
    }

    fn fresh(&self, entry: &Entry) -> Option<Bytes> {
        let cert = entry.record.cert.as_ref()?;
        (cert.not_after - now() > self.cfg.renew_before.as_secs() as i64)
            .then(|| entry.cert_json.clone())
            .flatten()
    }

    /// Updates RAM first (DNS sees the change immediately), then disk.
    async fn save(&self, hash: &str, record: Record) -> Result<Arc<Entry>> {
        let entry = self.build_entry(hash, record);
        self.cache.insert(hash.to_owned(), entry.clone()).await;
        self.store.put(hash, &entry.record).await?;
        Ok(entry)
    }

    async fn account(&self) -> Result<&instant_acme::Account> {
        let path = self.cfg.data_dir.join("account.json");
        let url = self.cfg.directory_url.clone();
        let email = self.cfg.email.clone();
        self.account
            .get_or_try_init(|| async move { acme::load_or_create_account(&path, &url, email.as_deref()).await })
            .await
    }

    /// Still valid (even if close to expiry): usable as a fallback when a refresh fails.
    fn not_expired(&self, entry: &Entry) -> Option<Bytes> {
        let cert = entry.record.cert.as_ref()?;
        (cert.not_after > now()).then(|| entry.cert_json.clone()).flatten()
    }

    /// Returns the certificate JSON response for this hash (same body whether it was just
    /// issued, refreshed or already stored):
    /// - none stored: issue one;
    /// - stored and far from expiry: return it;
    /// - stored and close to expiry: try to refresh; if that fails while the old one is still
    ///   valid, return the old one and wait `REFRESH_BACKOFF` before trying again.
    pub async fn certificate(&self, hash: &str) -> Result<Bytes> {
        let current = self.get(hash).await?;
        // Fast path: cached (or on disk) and far from expiry.
        if let Some(body) = self.fresh(&current) {
            return Ok(body);
        }
        let fallback = self.not_expired(&current);
        if let Some(body) = &fallback {
            if self.refresh_backoff.contains_key(hash) {
                return Ok(body.clone());
            }
        }

        let lock = self.issuing.get_with_by_ref(hash, async { Arc::default() }).await;
        let _guard = lock.lock().await;
        let result = self.issue(hash).await;
        self.issuing.invalidate(hash).await;

        match (result, fallback) {
            (Ok(body), _) => Ok(body),
            (Err(e), Some(old)) => {
                warn!("refresh failed for {hash}, serving the current certificate: {e:#}");
                self.refresh_backoff.insert(hash.to_owned(), ()).await;
                Ok(old)
            }
            (Err(e), None) => Err(e),
        }
    }

    async fn issue(&self, hash: &str) -> Result<Bytes> {
        let current = self.get(hash).await?;
        if let Some(body) = self.fresh(&current) {
            return Ok(body); // another request issued it while we were waiting for the lock
        }
        let mut record = current.record.clone();

        let names = self.names(hash);
        info!("issuing certificate for {names:?}");
        let pending = acme::start(self.account().await?, &names).await?;

        let mut cf_ids = Vec::new();
        if !pending.challenges.is_empty() {
            record.txt = pending.challenges.iter().map(|(_, v)| v.clone()).collect();
            self.save(hash, record.clone()).await?;

            if let Some(cf) = &self.cloudflare {
                for (name, value) in &pending.challenges {
                    cf_ids.push(cf.create_txt(name, value).await?);
                }
            }
            if !self.cfg.propagation_delay.is_zero() {
                tokio::time::sleep(self.cfg.propagation_delay).await;
            }
        }

        let result = acme::finish(pending).await;

        if let Some(cf) = &self.cloudflare {
            for id in cf_ids {
                if let Err(e) = cf.delete_record(&id).await {
                    warn!("could not delete Cloudflare TXT {id}: {e:#}");
                }
            }
        }

        let (chain, key) = result?;
        record.cert = Some(CertData::new(chain, key)?);
        let entry = self.save(hash, record).await?;
        Ok(entry.cert_json.clone().expect("certificate was just added"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(dir: &std::path::Path) -> AppState {
        let cfg = Config {
            base_domain: "klapz.direct".into(),
            wildcard: true,
            directory_url: "http://127.0.0.1:1/directory".into(), // unreachable on purpose
            email: None,
            data_dir: dir.to_owned(),
            renew_before: Duration::from_secs(30 * 86_400),
            propagation_delay: Duration::ZERO,
            cache_max_bytes: 50_000_000,
            token_length: 32,
        };
        AppState::new(cfg, Hasher::new(b"secret", 20), None)
    }

    #[tokio::test]
    async fn txt_and_certificate_from_disk() {
        let dir = std::env::temp_dir().join(format!("kdd-state-{}", std::process::id()));
        let st = state(&dir);
        let hash = st.hasher.subdomain("my-token");

        // Unknown name: nothing (and the miss is cached).
        assert!(st.txt_for_name(&format!("_acme-challenge.{hash}.klapz.direct.")).await.is_none());

        // Write a record, as after an issuance.
        let rec = Record {
            txt: vec!["txt-value".into()],
            cert: Some(CertData { not_after: now() + 60 * 86_400, chain: "CHAIN".into(), key: "KEY".into() }),
        };
        st.save(&hash, rec).await.unwrap();

        let e = st.txt_for_name(&format!("_ACME-challenge.{}.Klapz.Direct.", hash.to_uppercase())).await.unwrap();
        assert_eq!(e.record.txt, vec!["txt-value".to_string()]);
        assert!(st.txt_for_name("_acme-challenge.zzz.klapz.direct").await.is_none());
        assert!(st.txt_for_name(&format!("_acme-challenge.{hash}.other.com")).await.is_none());

        // Cache cleared: re-read from the .bin, and the still-valid certificate is returned without ACME.
        st.cache.invalidate_all();
        let body = st.certificate(&hash).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["certificate"], "CHAIN");
        assert_eq!(json["names"][0], format!("*.{hash}.klapz.direct"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_refresh_serves_current_certificate() {
        let dir = std::env::temp_dir().join(format!("kdd-refresh-{}", std::process::id()));
        let st = state(&dir);
        let hash = st.hasher.subdomain("my-token");
        // Valid for 5 more days: inside the 30-day renewal window, so a refresh is attempted.
        // ACME is unreachable in tests, so the refresh fails.
        let rec = Record {
            txt: vec![],
            cert: Some(CertData { not_after: now() + 5 * 86_400, chain: "OLD".into(), key: "KEY".into() }),
        };
        st.save(&hash, rec).await.unwrap();

        let json: serde_json::Value = serde_json::from_slice(&st.certificate(&hash).await.unwrap()).unwrap();
        assert_eq!(json["certificate"], "OLD");
        assert!(st.refresh_backoff.contains_key(&hash));
        // Second call: within the backoff, no new attempt, same body.
        let json: serde_json::Value = serde_json::from_slice(&st.certificate(&hash).await.unwrap()).unwrap();
        assert_eq!(json["certificate"], "OLD");

        // Expired certificate: no fallback, the error is returned.
        let other = st.hasher.subdomain("other-token");
        let rec = Record { txt: vec![], cert: Some(CertData { not_after: now() - 1, chain: "X".into(), key: "K".into() }) };
        st.save(&other, rec).await.unwrap();
        assert!(st.certificate(&other).await.is_err());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cache_bounded_in_bytes() {
        let dir = std::env::temp_dir().join(format!("kdd-cache-{}", std::process::id()));
        let mut st = state(&dir);
        st.cache = Cache::builder()
            .max_capacity(1_000_000)
            .weigher(|k: &String, v: &Arc<Entry>| v.weight(k))
            .build();
        let big = "x".repeat(10_000);
        for i in 0..500 {
            let rec = Record { txt: vec![], cert: Some(CertData { not_after: 0, chain: big.clone(), key: String::new() }) };
            st.cache.insert(format!("{i:020}"), st.build_entry("h", rec)).await;
        }
        st.cache.run_pending_tasks().await;
        assert!(st.cache.weighted_size() <= 1_000_000, "size = {}", st.cache.weighted_size());
        let _ = std::fs::remove_dir_all(dir);
    }
}
