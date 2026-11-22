use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Deterministic subdomain generator: HMAC-SHA256(secret, token), hex-encoded, truncated.
///
/// The same token always yields the same hash, but without the secret it can neither be
/// guessed nor traced back to the token. This matters because every issued certificate is
/// published in Certificate Transparency logs: the subdomain becomes public.
///
/// Perf: the keyed HMAC state is prepared once at startup; each request only clones it
/// (a few bytes) instead of re-hashing the key.
#[derive(Clone)]
pub struct Hasher {
    keyed: Hmac<Sha256>,
    len: usize,
}

impl Hasher {
    pub fn new(secret: &[u8], len: usize) -> Self {
        let keyed = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts keys of any size");
        // At least 4 chars for the ab/cd/ directory sharding, at most 63 (DNS label limit).
        Self { keyed, len: len.clamp(8, 63) }
    }

    pub fn subdomain(&self, token: &str) -> String {
        let mut mac = self.keyed.clone();
        mac.update(token.as_bytes());
        let mut h = hex::encode(mac.finalize().into_bytes());
        h.truncate(self.len);
        h
    }

    /// Checks that an externally supplied string looks like a hash
    /// (also guards against `../` in file paths).
    pub fn is_valid(&self, s: &str) -> bool {
        s.len() == self.len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_secret_dependent() {
        let h = Hasher::new(b"secret", 20);
        let a = h.subdomain("my-token");
        assert_eq!(a, h.subdomain("my-token"));
        assert_ne!(a, Hasher::new(b"other", 20).subdomain("my-token"));
        assert_ne!(a, h.subdomain("other-token"));
        assert_eq!(a.len(), 20);
        assert!(h.is_valid(&a));
        assert!(!h.is_valid("../../etc/passwd000"));
    }
}
