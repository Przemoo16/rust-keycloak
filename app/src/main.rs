use crate::state::AppState;
use axum::Router;

use crate::api::main::create_main_router;
use crate::api::oauth::create_oauth_router;

mod api;
mod config;
mod services;
mod state;

#[tokio::main]
async fn main() {
    let state = AppState::new();
    tracing_subscriber::fmt::init();
    let app = Router::new()
        .nest("/", create_main_router())
        .nest("/oauth", create_oauth_router())
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:80").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
