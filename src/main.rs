mod acme;
mod api;
mod cloudflare;
mod dns;
mod hash;
mod state;
mod store;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::info;

use crate::cloudflare::Cloudflare;
use crate::hash::Hasher;
use crate::state::{AppState, Config};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("variable d'environnement {key} manquante"))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_owned())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let directory_url = match env_or("ACME_DIRECTORY", "staging").as_str() {
        "production" => instant_acme::LetsEncrypt::Production.url().to_owned(),
        "staging" => instant_acme::LetsEncrypt::Staging.url().to_owned(),
        other => other.to_owned(), // URL d'un autre serveur ACME
    };

    // Cloudflare est optionnel : sans lui, c'est ton serveur DNS qui sert les TXT
    // (via AppState::txt_for_name), et il n'y a aucun délai de propagation.
    let cloudflare = match (std::env::var("CLOUDFLARE_API_TOKEN"), std::env::var("CLOUDFLARE_ZONE_ID")) {
        (Ok(token), Ok(zone)) if !token.is_empty() && !zone.is_empty() => Some(Cloudflare::new(token, zone)),
        _ => None,
    };
    let default_delay = if cloudflare.is_some() { "15" } else { "0" };

    let cfg = Config {
        base_domain: env("BASE_DOMAIN")?.trim_end_matches('.').to_ascii_lowercase(),
        wildcard: env_or("WILDCARD", "true") == "true",
        directory_url,
        email: std::env::var("ACME_EMAIL").ok().filter(|e| !e.is_empty()),
        data_dir: PathBuf::from(env_or("DATA_DIR", "./data")),
        renew_before: Duration::from_secs(env_or("RENEW_BEFORE_DAYS", "30").parse::<u64>()? * 86_400),
        propagation_delay: Duration::from_secs(env_or("DNS_PROPAGATION_SECONDS", default_delay).parse()?),
        cache_max_bytes: env_or("CACHE_MAX_MB", "50").parse::<u64>()? * 1_000_000,
    };
    let hasher = Hasher::new(env("HASH_SECRET")?.as_bytes(), env_or("HASH_LENGTH", "20").parse()?);

    info!("ACME : {} | Cloudflare : {}", cfg.directory_url, if cloudflare.is_some() { "oui" } else { "non" });
    let state = Arc::new(AppState::new(cfg, hasher, cloudflare));

    // Serveur DNS dans le même process : il lit le même cache, donc un TXT écrit
    // par l'API est servi immédiatement. DNS_LISTEN=off pour le désactiver.
    let dns_listen = env_or("DNS_LISTEN", "0.0.0.0:53");
    if dns_listen != "off" {
        let base = &state.cfg.base_domain;
        let dns_cfg = dns::DnsConfig {
            listen: dns_listen.parse().context("DNS_LISTEN invalide")?,
            ns: env_or("DNS_NS", &format!("ns1.{base}")).split(',').map(|s| s.trim().to_owned()).collect(),
            ns_ips: env_or("DNS_NS_IPS", "")
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().parse())
                .collect::<Result<_, _>>()
                .context("DNS_NS_IPS invalide")?,
        };
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = dns::serve(st, dns_cfg).await {
                tracing::error!("serveur DNS arrêté : {e:#}");
                std::process::exit(1);
            }
        });
    }

    let addr = env_or("LISTEN_ADDR", "0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("API sur {addr}");
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}
