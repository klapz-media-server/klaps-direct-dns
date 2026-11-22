use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::json;

const API: &str = "https://api.cloudflare.com/client/v4";

/// Client minimal de l'API DNS de Cloudflare : créer et supprimer les TXT `_acme-challenge`.
#[derive(Clone)]
pub struct Cloudflare {
    http: reqwest::Client,
    api_token: String,
    zone_id: String,
}

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    errors: serde_json::Value,
    result: Option<T>,
}

#[derive(Deserialize)]
struct CfRecord {
    id: String,
}

impl Cloudflare {
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self { http: reqwest::Client::new(), api_token, zone_id }
    }

    /// Crée un enregistrement TXT et renvoie son id (nécessaire pour le supprimer ensuite).
    pub async fn create_txt(&self, name: &str, value: &str) -> Result<String> {
        let url = format!("{API}/zones/{}/dns_records", self.zone_id);
        let body = json!({ "type": "TXT", "name": name, "content": format!("\"{value}\""), "ttl": 60 });
        let resp: CfResponse<CfRecord> = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await?
            .json()
            .await
            .context("réponse Cloudflare illisible")?;
        if !resp.success {
            bail!("Cloudflare a refusé la création du TXT {name} : {}", resp.errors);
        }
        Ok(resp.result.context("Cloudflare n'a pas renvoyé d'id")?.id)
    }

    pub async fn delete_record(&self, id: &str) -> Result<()> {
        let url = format!("{API}/zones/{}/dns_records/{id}", self.zone_id);
        let resp: CfResponse<serde_json::Value> =
            self.http.delete(url).bearer_auth(&self.api_token).send().await?.json().await?;
        if !resp.success {
            bail!("Cloudflare a refusé la suppression de {id} : {}", resp.errors);
        }
        Ok(())
    }
}
