use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};

use axum_extra::extract::cookie::{Cookie, CookieJar};
use jsonwebtoken::{
    decode, decode_header,
    errors::{Error, ErrorKind},
    Algorithm, DecodingKey, TokenData, Validation,
};
use reqwest::StatusCode;
use serde::Deserialize;
use time::Duration;

use crate::services::auth::{get_jwk, refresh_token, RefreshTokenParams};
use crate::state::AppState;

const AUTH_AUDIENCE: &str = "account"; // Default audience added by Keycloak

#[derive(Deserialize)]
pub struct Claims {}

pub enum AuthError {
    InvalidCredentials(String),
    InternalServerError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let response = match self {
            AuthError::InvalidCredentials(message) => {
                tracing::info!(message);
                let jar = CookieJar::new();
                let access_token_cookie = build_deletion_cookie("access_token");
                let refresh_token_cookie = build_deletion_cookie("refresh_token");
                (
                    jar.add(access_token_cookie).add(refresh_token_cookie),
                    Redirect::to("/"),
                )
                    .into_response()
            }
            AuthError::InternalServerError(message) => {
                tracing::error!(message);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        };
        return response;
    }
}

// TODO: Cache JWK response
// TODO: Save new tokens
// TODO: Redirect to login page if kid in the token is invalid. Currently it returns 500.
#[async_trait]
impl FromRequestParts<AppState> for Claims
where
    AppState: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, &state)
            .await
            .map_err(|err| {
                AuthError::InternalServerError(format!("Error when extracting cookies: {}", err))
            })?;

        let access_token = extract_token_from_cookies(&jar, "access_token")?;
        let decoder = get_access_token_decoder(&access_token, &state).await?;
        let access_token_data = decoder();

        match access_token_data {
            Ok(value) => Ok(value.claims),
            Err(err) => match err.kind() {
                ErrorKind::ExpiredSignature => {
                    let refresh_token_value = extract_token_from_cookies(&jar, "refresh_token")?;

                    let refresh_token_params = RefreshTokenParams {
                        refresh_token: &refresh_token_value,
                        client_id: &state.config.auth_client_id,
                        client_secret: &state.config.auth_client_secret,
                    };

                    let refresh_token_data = refresh_token(
                        &state.config.auth_service_internal_url,
                        &state.config.auth_realm,
                        refresh_token_params,
                        &state.http_client,
                    )
                    .await
                    .map_err(|err| {
                        AuthError::InvalidCredentials(format!(
                            "Error when refreshing access token: {}",
                            err
                        ))
                    })?;

                    tracing::info!("Access token refreshed successfully");

                    let decoder =
                        get_access_token_decoder(&refresh_token_data.access_token, &state).await?;
                    let access_token_data = decoder().map_err(|err| {
                        AuthError::InternalServerError(format!(
                            "Error when decoding new access token: {}",
                            err
                        ))
                    })?;
                    return Ok(access_token_data.claims);
                }
                _ => Err(AuthError::InvalidCredentials(format!(
                    "Error when decoding access token: {}",
                    err
                ))),
            },
        }
    }
}

fn extract_token_from_cookies<'a>(jar: &'a CookieJar, name: &str) -> Result<&'a str, AuthError> {
    let cookie = jar
        .get(name)
        .ok_or_else(|| AuthError::InvalidCredentials(format!("Missing '{}' in cookies", name)))?;
    return Ok(cookie.value());
}

async fn get_access_token_decoder<'a>(
    token: &'a str,
    state: &AppState,
) -> Result<impl FnOnce() -> Result<TokenData<Claims>, Error> + 'a, AuthError> {
    let header = decode_header(&token).map_err(|err| {
        AuthError::InvalidCredentials(format!("Error when decoding access token header: {}", err))
    })?;
    let kid = header.kid.ok_or_else(|| {
        AuthError::InvalidCredentials(format!("Missing kid in access token header"))
    })?;
    let jwk = get_jwk(
        &state.config.auth_service_internal_url,
        &state.config.auth_realm,
        &kid,
        &state.http_client,
    )
    .await
    .map_err(|err| AuthError::InternalServerError(format!("Error when retrieving jwk: {}", err)))?;
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|err| {
        AuthError::InternalServerError(format!("Error when creating decoding key: {}", err))
    })?;
    let algorithm = match jwk.alg.as_str() {
        "RS256" => Algorithm::RS256,
        _ => Algorithm::HS256,
    };
    let mut validation = Validation::new(algorithm);
    validation.set_audience(&[AUTH_AUDIENCE]);
    return Ok(move || decode::<Claims>(token, &decoding_key, &validation));
}

fn build_deletion_cookie(name: &str) -> Cookie {
    Cookie::build(name).max_age(Duration::seconds(-1)).build()
}
