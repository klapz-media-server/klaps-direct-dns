use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, RetryPolicy,
};
use tracing::info;

/// Charge le compte ACME depuis `account.json`, ou en crée un et le sauvegarde.
/// Toujours le même compte : Let's Encrypt applique ses limites par compte.
pub async fn load_or_create_account(path: &Path, directory_url: &str, email: Option<&str>) -> Result<Account> {
    if let Ok(raw) = tokio::fs::read_to_string(path).await {
        let creds: AccountCredentials = serde_json::from_str(&raw).context("account.json invalide")?;
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
    info!("nouveau compte ACME sauvegardé dans {}", path.display());
    Ok(account)
}

/// Une commande en cours : les TXT à publier avant d'appeler [`finish`].
pub struct Pending {
    order: Order,
    /// (nom de l'enregistrement, valeur), ex. ("_acme-challenge.abcd.example.com", "Xy...")
    pub challenges: Vec<(String, String)>,
}

/// Étape 1 : ouvre la commande et calcule les valeurs TXT (challenge DNS-01).
/// Pour `x.example.com` + `*.x.example.com`, il y a 2 valeurs sur le même nom.
pub async fn start(account: &Account, names: &[String]) -> Result<Pending> {
    let identifiers: Vec<Identifier> = names.iter().cloned().map(Identifier::Dns).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    let mut challenges = Vec::new();
    let mut authzs = order.authorizations();
    while let Some(authz) = authzs.next().await {
        let mut authz = authz?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue, // déjà validé récemment par LE
            s => bail!("autorisation dans un état inattendu : {s:?}"),
        }
        let challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("pas de challenge DNS-01 proposé"))?;
        // Pour *.x.example.com, l'identifiant est x.example.com (sans le "*.").
        let Identifier::Dns(domain) = challenge.identifier().identifier else {
            bail!("identifiant non DNS");
        };
        challenges.push((format!("_acme-challenge.{domain}"), challenge.key_authorization().dns_value()));
    }
    drop(authzs);
    Ok(Pending { order, challenges })
}

/// Étape 2 (une fois les TXT visibles dans le DNS) : valide et récupère le certificat.
/// Renvoie (chaîne PEM, clé privée PEM).
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
        bail!("commande ACME refusée (statut {status:?}) — TXT pas visible ou délai de propagation trop court ?");
    }
    // finalize() génère la clé privée (ECDSA P-256) et le CSR.
    let key = order.finalize().await?;
    let chain = order.poll_certificate(&retry).await?;
    Ok((chain, key))
}
