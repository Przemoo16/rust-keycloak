use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};

use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::StatusCode;
use serde::Deserialize;

use crate::services::auth::get_jwk;
use crate::state::AppState;

const AUTH_AUDIENCE: &str = "account"; // Default audience added by Keycloak

#[derive(Deserialize)]
pub struct Claims {}

#[async_trait]
impl FromRequestParts<AppState> for Claims
where
    AppState: Send + Sync,
{
    type Rejection = Response;

    // TODO: Support refresh token
    // TODO: Cache JWK response
    // TODO: Clear invalid tokens from cookies
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, &state)
            .await
            .map_err(|e| {
                tracing::error!("Error when extracting cookies: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Couldn't perform authentization",
                )
                    .into_response();
            })?;

        let cookie = jar.get("access_token").ok_or_else(|| {
            tracing::info!("Missing access token in cookies");
            return Redirect::to("/").into_response();
        })?;
        let token = cookie.value();

        let header = decode_header(&token).map_err(|e| {
            tracing::info!("Error when decoding token header: {}", e);
            return Redirect::to("/").into_response();
        })?;

        let kid = header.kid.ok_or_else(|| {
            tracing::info!("Missing kid in token header");
            return Redirect::to("/").into_response();
        })?;

        let jwk = get_jwk(
            &state.config.auth_service_internal_url,
            &state.config.auth_realm,
            &kid,
            &state.http_client,
        )
        .await
        .map_err(|e| {
            tracing::error!("Error when retrieving jwk: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't perform authentization",
            )
                .into_response();
        })?;

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            tracing::error!("Error when creating decoding key: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't perform authentization",
            )
                .into_response();
        })?;

        let algorithm = match jwk.alg.as_str() {
            "RS256" => Algorithm::RS256,
            _ => Algorithm::HS256,
        };

        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[AUTH_AUDIENCE]);

        let token_data = decode::<Claims>(&token, &decoding_key, &validation).map_err(|e| {
            tracing::info!("Error when decoding token: {}", e);
            return Redirect::to("/").into_response();
        })?;
        return Ok(token_data.claims);
    }
}
