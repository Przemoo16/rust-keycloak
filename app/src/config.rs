#[derive(Clone)]
pub struct Config {
    pub auth_service_public_url: String,
    pub auth_service_internal_url: String,
    pub auth_realm: String,
    pub auth_client_id: String,
    pub auth_client_secret: String,
    pub auth_redirect_uri: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            auth_service_public_url: read_env("AUTH_SERVICE_PUBLIC_URL"),
            auth_service_internal_url: read_env("AUTH_SERVICE_INTERNAL_URL"),
            auth_realm: read_env("AUTH_REALM"),
            auth_client_id: read_env("AUTH_CLIENT_ID"),
            auth_client_secret: read_env("AUTH_CLIENT_SECRET"),
            auth_redirect_uri: read_env("AUTH_REDIRECT_URI"),
        }
    }
}

fn read_env(key: &str) -> String {
    std::env::var(key).expect(&format!("Couldn't read {} env variable", key))
}
