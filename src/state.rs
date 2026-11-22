//! État partagé entre l'API et le serveur DNS.
//!
//! Disque = source de vérité (un `.bin` par hash). Devant, un cache RAM borné en octets
//! (50 Mo par défaut) : moka évince selon l'usage (TinyLFU : fréquence + récence), donc
//! les hash les plus demandés restent en mémoire. Les hash absents sont aussi mis en cache
//! (entrée vide, quelques octets) pour que des requêtes DNS sur des noms bidons ne
//! touchent pas le disque à chaque fois.

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
    /// En minuscules, sans point final, ex. "certs.example.com".
    pub base_domain: String,
    pub wildcard: bool,
    pub directory_url: String,
    pub email: Option<String>,
    pub data_dir: PathBuf,
    pub renew_before: Duration,
    pub propagation_delay: Duration,
    pub cache_max_bytes: u64,
}

/// Ce qu'on garde en mémoire pour un hash. La réponse JSON du certificat est
/// sérialisée une seule fois, puis renvoyée telle quelle (clone d'un `Bytes` = compteur).
pub struct Entry {
    pub record: Record,
    pub cert_json: Option<Bytes>,
}

impl Entry {
    /// Poids approximatif en RAM, pour la limite du cache.
    fn weight(&self, key: &str) -> u32 {
        const OVERHEAD: usize = 256; // structures internes du cache, Arc, Vec...
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
    /// Un verrou par émission en cours : deux requêtes simultanées pour le même token
    /// ne déclenchent qu'une seule commande Let's Encrypt. Purgé quand l'émission se termine.
    issuing: Cache<String, Arc<Mutex<()>>>,
    account: OnceCell<instant_acme::Account>,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

impl AppState {
    pub fn new(cfg: Config, hasher: Hasher, cloudflare: Option<Cloudflare>) -> Self {
        let cache = Cache::builder()
            .max_capacity(cfg.cache_max_bytes)
            .weigher(|k: &String, v: &Arc<Entry>| v.weight(k))
            .build();
        info!("cache RAM : {} Mo max", cfg.cache_max_bytes / 1_000_000);
        Self {
            store: Store::new(cfg.data_dir.join("certs")),
            cfg,
            hasher,
            cloudflare,
            cache,
            issuing: Cache::builder().time_to_idle(Duration::from_secs(600)).build(),
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
            Bytes::from(serde_json::to_vec(&body).expect("JSON toujours sérialisable"))
        });
        Arc::new(Entry { record, cert_json })
    }

    /// Entrée d'un hash (déjà validé) : depuis la RAM, sinon depuis le disque.
    /// Si plusieurs requêtes ratent le cache en même temps, une seule lit le disque.
    pub async fn get(&self, hash: &str) -> Result<Arc<Entry>> {
        self.cache
            .try_get_with_by_ref(hash, async {
                let record = self.store.get(hash).await?.unwrap_or_default();
                Ok::<_, anyhow::Error>(self.build_entry(hash, record))
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e:#}"))
    }

    /// Pour le serveur DNS : `_acme-challenge.<hash>.<base_domain>` -> entrée (lire `record.txt`).
    /// Insensible à la casse, accepte le point final.
    #[allow(dead_code)] // pratique pour un autre frontal DNS ; dns.rs résout directement
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

    /// Met à jour la RAM tout de suite (le DNS voit le changement immédiatement), puis le disque.
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

    /// Renvoie la réponse JSON du certificat pour ce hash, en l'émettant si besoin.
    pub async fn certificate(&self, hash: &str) -> Result<Bytes> {
        // Chemin rapide : en cache (ou sur disque) et encore valide.
        if let Some(body) = self.fresh(&*self.get(hash).await?) {
            return Ok(body);
        }

        let lock = self.issuing.get_with_by_ref(hash, async { Arc::default() }).await;
        let _guard = lock.lock().await;
        let result = self.issue(hash).await;
        self.issuing.invalidate(hash).await;
        result
    }

    async fn issue(&self, hash: &str) -> Result<Bytes> {
        let current = self.get(hash).await?;
        if let Some(body) = self.fresh(&current) {
            return Ok(body); // une autre requête vient de l'émettre pendant qu'on attendait le verrou
        }
        let mut record = current.record.clone();

        let names = self.names(hash);
        info!("émission d'un certificat pour {names:?}");
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
                    warn!("suppression du TXT Cloudflare {id} impossible : {e:#}");
                }
            }
        }

        let (chain, key) = result?;
        record.cert = Some(CertData::new(chain, key)?);
        let entry = self.save(hash, record).await?;
        Ok(entry.cert_json.clone().expect("le certificat vient d'être ajouté"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(dir: &std::path::Path) -> AppState {
        let cfg = Config {
            base_domain: "certs.example.com".into(),
            wildcard: true,
            directory_url: String::new(),
            email: None,
            data_dir: dir.to_owned(),
            renew_before: Duration::from_secs(30 * 86_400),
            propagation_delay: Duration::ZERO,
            cache_max_bytes: 50_000_000,
        };
        AppState::new(cfg, Hasher::new(b"secret", 20), None)
    }

    #[tokio::test]
    async fn txt_et_certificat_depuis_le_disque() {
        let dir = std::env::temp_dir().join(format!("kdd-state-{}", std::process::id()));
        let st = state(&dir);
        let hash = st.hasher.subdomain("mon-token");

        // Nom inconnu : rien (et l'absence est mise en cache).
        assert!(st.txt_for_name(&format!("_acme-challenge.{hash}.certs.example.com.")).await.is_none());

        // On écrit un enregistrement sur disque, comme après une émission.
        let rec = Record {
            txt: vec!["valeur-txt".into()],
            cert: Some(CertData { not_after: now() + 60 * 86_400, chain: "CHAIN".into(), key: "KEY".into() }),
        };
        st.save(&hash, rec).await.unwrap();

        let e = st.txt_for_name(&format!("_ACME-challenge.{}.Certs.Example.com.", hash.to_uppercase())).await.unwrap();
        assert_eq!(e.record.txt, vec!["valeur-txt".to_string()]);
        assert!(st.txt_for_name("_acme-challenge.zzz.certs.example.com").await.is_none());
        assert!(st.txt_for_name(&format!("_acme-challenge.{hash}.autre.com")).await.is_none());

        // Cache vidé : relu depuis le .bin, et le certificat encore valide est renvoyé sans ACME.
        st.cache.invalidate_all();
        let body = st.certificate(&hash).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["certificate"], "CHAIN");
        assert_eq!(json["names"][0], format!("*.{hash}.certs.example.com"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cache_borne_en_octets() {
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
        assert!(st.cache.weighted_size() <= 1_000_000, "taille = {}", st.cache.weighted_size());
        let _ = std::fs::remove_dir_all(dir);
    }
}
