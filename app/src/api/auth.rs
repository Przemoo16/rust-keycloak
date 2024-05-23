use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use serde::Deserialize;

use crate::services::auth::{exchange_code_for_token, TokenParams};
use crate::state::AppState;

pub fn create_auth_router() -> Router<AppState> {
    Router::new().route("/callback", get(callback))
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    code: String,
}

async fn callback(
    Query(auth_response): Query<AuthResponse>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let token_params = TokenParams {
        code: &auth_response.code,
        client_id: &state.config.auth_client_id,
        client_secret: &state.config.auth_client_secret,
        redirect_uri: &state.config.auth_redirect_uri,
    };
    let token_result = exchange_code_for_token(
        &state.config.auth_service_private_url,
        &state.config.auth_realm,
        token_params,
        &state.http_client,
    )
    .await;
    match token_result {
        Ok((_access_token, _refresh_token)) => return Redirect::to("/protected").into_response(),
        Err(e) => {
            tracing::error!("Error when exchanging code for token: {}", e);
            return (StatusCode::BAD_REQUEST, "Couldn't exchange code for token").into_response();
        }
    }
}
