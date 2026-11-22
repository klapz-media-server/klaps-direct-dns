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
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing Authorization: Bearer <token> header"))
}

/// TODO: check here that the token really exists on your side (database, allowlist, JWT...).
/// Without this, anyone can exhaust your Let's Encrypt quota with bogus tokens.
async fn token_is_valid(_token: &str) -> bool {
    true
}

/// GET /subdomain: the token's hash and domain, without issuing anything.
async fn get_subdomain(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let hash = st.hasher.subdomain(bearer(&headers)?);
    Ok(Json(json!({ "domain": st.domain(&hash), "hash": hash })).into_response())
}

/// POST /certificate: the stored certificate for this hash, or a new one if missing or expiring soon.
async fn post_certificate(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let token = bearer(&headers)?;
    if !token_is_valid(token).await {
        return Err(ApiError(StatusCode::FORBIDDEN, "invalid token"));
    }
    let hash = st.hasher.subdomain(token);
    match st.certificate(&hash).await {
        Ok(body) => Ok(json_bytes(body)),
        Err(e) => {
            error!("certificate failed for {hash}: {e:#}");
            Err(ApiError(StatusCode::BAD_GATEWAY, "could not obtain certificate"))
        }
    }
}

/// GET /txt/{hash}: the stored `_acme-challenge` TXT values (public anyway via DNS).
async fn get_txt(State(st): State<Arc<AppState>>, Path(hash): Path<String>) -> Result<Response, ApiError> {
    if !st.hasher.is_valid(&hash) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid hash"));
    }
    let entry = st.get(&hash).await.ok().filter(|e| !e.record.txt.is_empty());
    let Some(entry) = entry else {
        return Err(ApiError(StatusCode::NOT_FOUND, "no TXT for this hash"));
    };
    Ok(Json(json!({
        "name": format!("_acme-challenge.{}", st.domain(&hash)),
        "values": entry.record.txt,
    }))
    .into_response())
}
