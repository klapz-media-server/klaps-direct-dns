use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, RetryPolicy,
};
use tracing::info;

/// Loads the ACME account from `account.json`, or creates one and saves it.
/// Always reuse the same account: Let's Encrypt applies some limits per account.
pub async fn load_or_create_account(path: &Path, directory_url: &str, email: Option<&str>) -> Result<Account> {
    if let Ok(raw) = tokio::fs::read_to_string(path).await {
        let creds: AccountCredentials = serde_json::from_str(&raw).context("invalid account.json")?;
        return Ok(Account::builder()?.from_credentials(creds).await?);
    }

    let contact = email.map(|e| format!("mailto:{e}"));
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, creds) = Account::builder()?
        .create(
            &NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false },
            directory_url.to_owned(),
            None,
        )
        .await?;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, serde_json::to_string_pretty(&creds)?).await?;
    info!("new ACME account saved to {}", path.display());
    Ok(account)
}

/// An order in progress: the TXT records to publish before calling [`finish`].
pub struct Pending {
    order: Order,
    /// (record name, value), e.g. ("_acme-challenge.abcd.klapz.direct", "Xy...")
    pub challenges: Vec<(String, String)>,
}

/// Step 1: opens the order and computes the TXT values (DNS-01 challenge).
/// For `x.klapz.direct` + `*.x.klapz.direct` there are 2 values on the same name.
pub async fn start(account: &Account, names: &[String]) -> Result<Pending> {
    let identifiers: Vec<Identifier> = names.iter().cloned().map(Identifier::Dns).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    let mut challenges = Vec::new();
    let mut authzs = order.authorizations();
    while let Some(authz) = authzs.next().await {
        let mut authz = authz?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue, // recently validated by LE already
            s => bail!("authorization in unexpected state: {s:?}"),
        }
        let challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("no DNS-01 challenge offered"))?;
        // For *.x.klapz.direct the identifier is x.klapz.direct (without the "*.").
        let Identifier::Dns(domain) = challenge.identifier().identifier else {
            bail!("non-DNS identifier");
        };
        challenges.push((format!("_acme-challenge.{domain}"), challenge.key_authorization().dns_value()));
    }
    drop(authzs);
    Ok(Pending { order, challenges })
}

/// Step 2 (once the TXT records are visible in DNS): validates and fetches the certificate.
/// Returns (PEM chain, PEM private key).
pub async fn finish(mut pending: Pending) -> Result<(String, String)> {
    let order = &mut pending.order;
    let mut authzs = order.authorizations();
    while let Some(authz) = authzs.next().await {
        let mut authz = authz?;
        if authz.status != AuthorizationStatus::Pending {
            continue;
        }
        if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
            challenge.set_ready().await?;
        }
    }
    drop(authzs);

    let retry = RetryPolicy::default().timeout(Duration::from_secs(120));
    let status = order.poll_ready(&retry).await?;
    if status != OrderStatus::Ready {
        bail!("ACME order rejected (status {status:?}) — TXT not visible, or propagation delay too short?");
    }
    // finalize() generates the private key (ECDSA P-256) and the CSR.
    let key = order.finalize().await?;
    let chain = order.poll_certificate(&retry).await?;
    Ok((chain, key))
}
