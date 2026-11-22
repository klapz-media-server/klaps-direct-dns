use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Générateur de sous-domaine déterministe : HMAC-SHA256(secret, token), en hex, tronqué.
///
/// Le même token donne toujours le même hash, mais sans le secret on ne peut ni le deviner
/// ni remonter au token. C'est important parce que chaque certificat est publié dans les
/// logs Certificate Transparency : le sous-domaine devient public.
///
/// Perf : l'état HMAC avec la clé est préparé une seule fois au démarrage ; chaque requête
/// ne fait qu'un clone (quelques octets) au lieu de re-hasher la clé.
#[derive(Clone)]
pub struct Hasher {
    keyed: Hmac<Sha256>,
    len: usize,
}

impl Hasher {
    pub fn new(secret: &[u8], len: usize) -> Self {
        let keyed = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepte toute taille de clé");
        // 4 caractères minimum pour le découpage en dossiers ab/cd/, 63 max (label DNS).
        Self { keyed, len: len.clamp(8, 63) }
    }

    pub fn subdomain(&self, token: &str) -> String {
        let mut mac = self.keyed.clone();
        mac.update(token.as_bytes());
        let mut h = hex::encode(mac.finalize().into_bytes());
        h.truncate(self.len);
        h
    }

    /// Vérifie qu'une chaîne venant de l'extérieur a bien la forme d'un hash
    /// (protège aussi contre les `../` dans les chemins).
    pub fn is_valid(&self, s: &str) -> bool {
        s.len() == self.len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministe_et_dependant_du_secret() {
        let h = Hasher::new(b"secret", 20);
        let a = h.subdomain("mon-token");
        assert_eq!(a, h.subdomain("mon-token"));
        assert_ne!(a, Hasher::new(b"autre", 20).subdomain("mon-token"));
        assert_ne!(a, h.subdomain("autre-token"));
        assert_eq!(a.len(), 20);
        assert!(h.is_valid(&a));
        assert!(!h.is_valid("../../etc/passwd000"));
    }
}
