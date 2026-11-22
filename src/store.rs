//! Stockage hash -> enregistrement binaire, un fichier par hash :
//!
//!   data/certs/ab/cd/abcd1234....bin
//!
//! Format (entiers en little-endian) :
//!
//!   magic      4 octets   "CRT\x01"
//!   flags      u8         bit 0 = un certificat est présent
//!   n_txt      u16        nombre de valeurs TXT
//!   n_txt × { len u16, octets UTF-8 }
//!   si certificat :
//!     not_after  i64      expiration (timestamp Unix, secondes)
//!     chain      u32 len + PEM
//!     key        u32 len + PEM
//!
//! Le TXT est écrit dès le challenge (avant que le certificat existe), puis le
//! certificat s'ajoute dans le même fichier.

use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{bail, ensure, Context, Result};
use x509_parser::pem::parse_x509_pem;

const MAGIC: &[u8; 4] = b"CRT\x01";
const HAS_CERT: u8 = 1;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    pub txt: Vec<String>,
    pub cert: Option<CertData>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CertData {
    pub not_after: i64,
    pub chain: String,
    pub key: String,
}

impl CertData {
    /// L'expiration est lue une seule fois, à l'émission, puis stockée dans le fichier.
    pub fn new(chain: String, key: String) -> Result<Self> {
        let (_, pem) = parse_x509_pem(chain.as_bytes()).context("PEM invalide")?;
        let not_after = pem.parse_x509().context("X.509 invalide")?.validity().not_after.timestamp();
        Ok(Self { not_after, chain, key })
    }
}

impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let cert_len = self.cert.as_ref().map_or(0, |c| 16 + c.chain.len() + c.key.len());
        let txt_len: usize = self.txt.iter().map(|t| 2 + t.len()).sum();
        let mut out = Vec::with_capacity(7 + txt_len + cert_len);
        out.extend_from_slice(MAGIC);
        out.push(if self.cert.is_some() { HAS_CERT } else { 0 });
        out.extend_from_slice(&(self.txt.len() as u16).to_le_bytes());
        for t in &self.txt {
            out.extend_from_slice(&(t.len() as u16).to_le_bytes());
            out.extend_from_slice(t.as_bytes());
        }
        if let Some(c) = &self.cert {
            out.extend_from_slice(&c.not_after.to_le_bytes());
            for s in [&c.chain, &c.key] {
                out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader(buf);
        ensure!(r.take(4)? == MAGIC, "magic invalide");
        let flags = r.take(1)?[0];
        let n_txt = u16::from_le_bytes(r.array()?);
        let mut txt = Vec::with_capacity(n_txt as usize);
        for _ in 0..n_txt {
            let len = u16::from_le_bytes(r.array()?) as usize;
            txt.push(r.string(len)?);
        }
        let cert = if flags & HAS_CERT != 0 {
            let not_after = i64::from_le_bytes(r.array()?);
            let len = u32::from_le_bytes(r.array()?) as usize;
            let chain = r.string(len)?;
            let len = u32::from_le_bytes(r.array()?) as usize;
            let key = r.string(len)?;
            Some(CertData { not_after, chain, key })
        } else {
            None
        };
        ensure!(r.0.is_empty(), "octets en trop à la fin du fichier");
        Ok(Self { txt, cert })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("fichier tronqué");
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn string(&mut self, n: usize) -> Result<String> {
        Ok(std::str::from_utf8(self.take(n)?)?.to_owned())
    }
}

#[derive(Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// `ab/cd/abcd....bin` — le hash doit déjà être validé (hex, ≥ 4 caractères).
    pub fn path(&self, hash: &str) -> PathBuf {
        self.root.join(&hash[0..2]).join(&hash[2..4]).join(format!("{hash}.bin"))
    }

    pub async fn put(&self, hash: &str, record: &Record) -> Result<()> {
        write_atomic(self.path(hash), record.encode()).await
    }

    /// Lit l'enregistrement d'un hash sur disque (`None` s'il n'existe pas).
    pub async fn get(&self, hash: &str) -> Result<Option<Record>> {
        let path = self.path(hash);
        match tokio::fs::read(&path).await {
            Ok(buf) => Ok(Some(
                Record::decode(&buf).with_context(|| format!("fichier corrompu : {}", path.display()))?,
            )),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("lecture de {}", path.display())),
        }
    }
}

/// Écriture atomique : fichier .tmp puis rename. On voit soit l'ancien fichier entier,
/// soit le nouveau, jamais un fichier à moitié écrit. Mode 0600 : il contient la clé privée.
async fn write_atomic(path: PathBuf, content: Vec<u8>) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(path.parent().unwrap())?;
        let tmp = path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&content)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour_binaire() {
        let only_txt = Record { txt: vec!["abc".into(), "def".into()], cert: None };
        assert_eq!(Record::decode(&only_txt.encode()).unwrap(), only_txt);

        let full = Record {
            txt: vec!["xyz".into()],
            cert: Some(CertData { not_after: 1_800_000_000, chain: "CHAIN".into(), key: "KEY".into() }),
        };
        assert_eq!(Record::decode(&full.encode()).unwrap(), full);

        let mut bad = full.encode();
        bad.pop();
        assert!(Record::decode(&bad).is_err());
    }

    #[tokio::test]
    async fn ecriture_puis_chargement() {
        let dir = std::env::temp_dir().join(format!("kdd-test-{}", std::process::id()));
        let store = Store::new(dir.clone());
        let rec = Record { txt: vec!["v".into()], cert: None };
        store.put("abcdef0123", &rec).await.unwrap();
        assert!(dir.join("ab/cd/abcdef0123.bin").exists());
        assert_eq!(store.get("abcdef0123").await.unwrap(), Some(rec));
        assert_eq!(store.get("ffffff0000").await.unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
