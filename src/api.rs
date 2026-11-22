use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use bytes::Bytes;
use serde_json::json;
use tracing::error;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/subdomain", get(get_subdomain))
        .route("/certificate", put(put_certificate))
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

/// Extracts the bearer token and checks it has exactly `TOKEN_LENGTH` characters.
fn token<'a>(st: &AppState, headers: &'a HeaderMap) -> Result<&'a str, ApiError> {
    let token = bearer(headers)?;
    if !has_length(token, st.cfg.token_length) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "token has the wrong length"));
    }
    Ok(token)
}

/// Counts characters (not bytes), stopping early so oversized input costs nothing.
fn has_length(token: &str, len: usize) -> bool {
    token.len() >= len && token.chars().take(len + 1).count() == len
}

/// TODO: check here that the token really exists on your side (database, allowlist, JWT...).
/// Without this, anyone can exhaust your Let's Encrypt quota with bogus tokens.
async fn token_is_valid(_token: &str) -> bool {
    true
}

/// GET /subdomain: the token's hash and domain, without issuing anything.
async fn get_subdomain(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let hash = st.hasher.subdomain(token(&st, &headers)?);
    Ok(Json(json!({ "domain": st.domain(&hash), "hash": hash })).into_response())
}

/// PUT /certificate: idempotent. Issues the certificate if missing, tries to refresh it when
/// close to expiry (falling back to the current one if that fails), and always returns the
/// same body.
async fn put_certificate(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let token = token(&st, &headers)?;
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

#[cfg(test)]
mod tests {
    use super::has_length;

    #[test]
    fn exact_token_length() {
        assert!(has_length("abcd", 4));
        assert!(!has_length("abc", 4));
        assert!(!has_length("abcde", 4));
        assert!(has_length("éèàù", 4)); // characters, not bytes
        assert!(!has_length(&"x".repeat(10_000), 32));
    }
}
