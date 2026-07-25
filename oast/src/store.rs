//! Multi-tenant, zero-knowledge interaction store.
//!
//! A client (a scan) `register`s a correlation id with an RSA public key and a
//! secret. Callbacks to `<corr><rand>.<domain>` are matched to the correlation id,
//! sealed to that public key, and stored. Only the holder of the secret can poll
//! (anti-drain) and only the holder of the private key can read (confidentiality).
//! Callbacks whose correlation id is not registered are dropped, which is what
//! stops the public callback surface being abused as a generic relay.

use crate::crypto;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Correlation id length: the leading chars of the callback's correlation label.
pub const CORR_LEN: usize = 20;

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

/// The plaintext interaction. This is what gets sealed; the server never persists
/// it in the clear.
#[derive(Serialize)]
pub struct Interaction {
    /// "http" | "https" | "dns"
    pub protocol: String,
    pub full_host: String,
    pub remote_addr: String,
    pub at_unix: u64,
    pub detail: String,
    pub raw: String,
}

struct Registration {
    pubkey: String, // base64 PKCS#1 DER
    secret_hash: [u8; 32],
    expires_at: u64,
}

/// A stored, sealed interaction. `enc` is the crypto blob {k,n,c}; `protocol` and
/// `at_unix` are kept in the clear only as non-sensitive envelope metadata.
#[derive(Clone, Serialize)]
pub struct Sealed {
    pub protocol: String,
    pub at_unix: u64,
    pub enc: String,
}

pub struct Store {
    regs: Mutex<HashMap<String, Registration>>,
    interactions: Mutex<HashMap<String, Vec<Sealed>>>,
    ttl_secs: u64,
    cap_per_corr: usize,
}

impl Store {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            regs: Mutex::new(HashMap::new()),
            interactions: Mutex::new(HashMap::new()),
            ttl_secs,
            cap_per_corr: 500,
        }
    }

    /// Register a correlation id with a public key + secret. False if the pubkey is
    /// malformed.
    pub fn register(&self, corr_id: &str, pubkey: &str, secret: &str) -> bool {
        if corr_id.len() < CORR_LEN || !crypto::valid_pubkey(pubkey) {
            return false;
        }
        if let Ok(mut m) = self.regs.lock() {
            m.insert(
                corr_id.to_string(),
                Registration {
                    pubkey: pubkey.to_string(),
                    secret_hash: sha256(secret.as_bytes()),
                    expires_at: now_unix() + self.ttl_secs,
                },
            );
        }
        true
    }

    pub fn deregister(&self, corr_id: &str, secret: &str) -> bool {
        if !self.check_secret(corr_id, secret) {
            return false;
        }
        if let Ok(mut m) = self.regs.lock() {
            m.remove(corr_id);
        }
        if let Ok(mut i) = self.interactions.lock() {
            i.remove(corr_id);
        }
        true
    }

    fn check_secret(&self, corr_id: &str, secret: &str) -> bool {
        if let Ok(m) = self.regs.lock() {
            if let Some(r) = m.get(corr_id) {
                return r.secret_hash == sha256(secret.as_bytes());
            }
        }
        false
    }

    /// Seal an interaction to its correlation's public key and store it. Drops the
    /// interaction if the correlation id is unregistered or expired.
    pub fn capture(&self, corr_id: &str, interaction: &Interaction) {
        let pubkey = {
            let m = match self.regs.lock() {
                Ok(m) => m,
                Err(_) => return,
            };
            match m.get(corr_id) {
                Some(r) if r.expires_at > now_unix() => r.pubkey.clone(),
                _ => return, // unregistered / expired -> drop (abuse guard)
            }
        };
        let plaintext = match serde_json::to_vec(interaction) {
            Ok(p) => p,
            Err(_) => return,
        };
        let Some(enc) = crypto::seal_to_pubkey(&pubkey, &plaintext) else {
            return;
        };
        if let Ok(mut i) = self.interactions.lock() {
            let v = i.entry(corr_id.to_string()).or_default();
            v.push(Sealed {
                protocol: interaction.protocol.clone(),
                at_unix: interaction.at_unix,
                enc,
            });
            while v.len() > self.cap_per_corr {
                v.remove(0);
            }
        }
        tracing::info!(corr = %corr_id, protocol = %interaction.protocol, from = %interaction.remote_addr, "oast interaction sealed");
    }

    /// Drain and return the sealed interactions for a correlation id, if the secret
    /// matches.
    pub fn poll(&self, corr_id: &str, secret: &str) -> Option<Vec<Sealed>> {
        if !self.check_secret(corr_id, secret) {
            return None;
        }
        if let Ok(mut i) = self.interactions.lock() {
            return Some(i.remove(corr_id).unwrap_or_default());
        }
        Some(Vec::new())
    }

    pub async fn gc_loop(&self) {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = now_unix();
            let mut expired: Vec<String> = Vec::new();
            if let Ok(mut m) = self.regs.lock() {
                m.retain(|k, r| {
                    let live = r.expires_at > now;
                    if !live {
                        expired.push(k.clone());
                    }
                    live
                });
            }
            if !expired.is_empty() {
                if let Ok(mut i) = self.interactions.lock() {
                    for k in &expired {
                        i.remove(k);
                    }
                }
            }
        }
    }
}

/// Extract the 20-char correlation id from a callback host of the form
/// `[extra-labels.]<corr><rand>.<domain>`. Robust to case (DNS 0x20), extra
/// prepended labels (the correlation label is the one adjacent to the domain), and
/// a trailing dot. Returns None if the host is not under the domain or the
/// correlation label is too short.
pub fn corr_from_host(host: &str, domain: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let d = domain.trim().trim_matches('.').to_ascii_lowercase();
    if d.is_empty() || h == d {
        return None;
    }
    let prefix = h.strip_suffix(&d)?.strip_suffix('.')?;
    // The correlation label sits directly under the domain: the rightmost label.
    let corr_label = prefix.rsplit('.').next()?;
    if corr_label.len() < CORR_LEN {
        return None;
    }
    Some(corr_label[..CORR_LEN].to_string())
}

/// Try to extract a correlation id under any domain in the pool. One box can back
/// several delegated OAST domains (so callbacks are not all concentrated on a
/// single domain a WAF could blocklist); they share this one store and poll API.
pub fn corr_from_any(host: &str, domains: &[String]) -> Option<String> {
    domains.iter().find_map(|d| corr_from_host(host, d))
}
