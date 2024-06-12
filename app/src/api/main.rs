use axum::{extract::State, response::Html, routing::get, Router};

use crate::api::extractors::Claims;
use crate::services::auth::get_auth_url;
use crate::state::AppState;

pub fn create_main_router() -> Router<AppState> {
    Router::new()
        .route("/", get(homepage))
        .route("/protected", get(protected))
}

async fn homepage(State(state): State<AppState>) -> Html<String> {
    let auth_url = get_auth_url(
        &state.config.auth_service_public_url,
        &state.config.auth_realm,
        &state.config.auth_client_id,
        &state.config.auth_redirect_uri,
    );
    Html(format!(
        "<p>Welcome!</p>
        <a href=\"{url}\">
            Click here to sign into!
        </a>",
        url = auth_url
    ))
}

async fn protected(_claims: Claims) -> Html<&'static str> {
    Html("<p>Protected content</p>")
}
