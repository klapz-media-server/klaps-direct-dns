use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use serde_json::json;
use tracing::error;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/subdomain", get(get_subdomain))
        .route("/certificate", post(post_certificate))
        .route("/txt/{hash}", get(get_txt))
        .with_state(state)
}

pub struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn json_bytes(body: Bytes) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "en-tête Authorization: Bearer <token> manquant"))
}

/// À adapter : vérifie ici que le token existe vraiment chez toi (base, liste, JWT...).
/// Sans contrôle, n'importe qui peut épuiser tes quotas Let's Encrypt avec des tokens bidons.
async fn token_is_valid(_token: &str) -> bool {
    true
}

/// GET /subdomain : le hash et le domaine du token, sans rien émettre.
async fn get_subdomain(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let hash = st.hasher.subdomain(bearer(&headers)?);
    Ok(Json(json!({ "domain": st.domain(&hash), "hash": hash })).into_response())
}

/// POST /certificate : le certificat stocké pour ce hash, ou un nouveau s'il manque ou expire bientôt.
async fn post_certificate(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let token = bearer(&headers)?;
    if !token_is_valid(token).await {
        return Err(ApiError(StatusCode::FORBIDDEN, "token invalide"));
    }
    let hash = st.hasher.subdomain(token);
    match st.certificate(&hash).await {
        Ok(body) => Ok(json_bytes(body)),
        Err(e) => {
            error!("échec pour {hash} : {e:#}");
            Err(ApiError(StatusCode::BAD_GATEWAY, "impossible d'obtenir le certificat"))
        }
    }
}

/// GET /txt/{hash} : les valeurs TXT `_acme-challenge` stockées (publiques de toute façon via le DNS).
async fn get_txt(State(st): State<Arc<AppState>>, Path(hash): Path<String>) -> Result<Response, ApiError> {
    if !st.hasher.is_valid(&hash) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "hash invalide"));
    }
    let entry = st.get(&hash).await.ok().filter(|e| !e.record.txt.is_empty());
    let Some(entry) = entry else {
        return Err(ApiError(StatusCode::NOT_FOUND, "aucun TXT pour ce hash"));
    };
    Ok(Json(json!({
        "name": format!("_acme-challenge.{}", st.domain(&hash)),
        "values": entry.record.txt,
    }))
    .into_response())
}
