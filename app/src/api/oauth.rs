use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use time::Duration;

use crate::services::auth::{obtain_tokens, ObtainTokensError, ObtainTokensParams};
use crate::state::AppState;

const TOKEN_COOKIES_MAX_AGE_DAYS: i64 = 7;

pub fn create_oauth_router() -> Router<AppState> {
    Router::new().route("/callback", get(callback))
}

#[derive(Deserialize)]
struct AuthResponse {
    code: String,
}

async fn callback(
    Query(auth_response): Query<AuthResponse>,
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse {
    let params = ObtainTokensParams {
        code: &auth_response.code,
        client_id: &state.config.auth_client_id,
        client_secret: &state.config.auth_client_secret,
        redirect_uri: &state.config.auth_redirect_uri,
    };
    let tokens = obtain_tokens(
        &state.config.auth_service_internal_url,
        &state.config.auth_realm,
        params,
        &state.http_client,
    )
    .await;
    match tokens {
        Ok(value) => {
            let access_token_cookie = build_token_cookie("access_token", value.access_token);
            let refresh_token_cookie = build_token_cookie("refresh_token", value.refresh_token);
            return (
                jar.add(access_token_cookie).add(refresh_token_cookie),
                Redirect::to("/protected"),
            )
                .into_response();
        }
        Err(err) => match err {
            ObtainTokensError::InvalidRequestError(_) => {
                tracing::info!("Invalid request when obtaining tokens: {}", err);
                return (StatusCode::BAD_REQUEST, "Invalid request to obtain tokens")
                    .into_response();
            }
            _ => {
                tracing::error!("Error when obtaining tokens: {}", err);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Couldn't obtain tokens")
                    .into_response();
            }
        },
    }
}

fn build_token_cookie(key: &str, value: String) -> Cookie {
    Cookie::build((key, value))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::days(TOKEN_COOKIES_MAX_AGE_DAYS))
        .build()
}
