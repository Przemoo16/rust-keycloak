use reqwest::{Client, Error};
use serde::Deserialize;

pub fn get_auth_url(base_url: &str, realm: &str, client_id: &str, redirect_uri: &str) -> String {
    format!("{base_url}/realms/{realm}/protocol/openid-connect/auth?response_type=code&scope=openid&client_id={client_id}&redirect_uri={redirect_uri}", base_url=base_url, realm=realm, client_id=client_id, redirect_uri=redirect_uri)
}

pub struct TokenParams<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
}

pub async fn exchange_code_for_token(
    base_url: &str,
    realm: &str,
    token_params: TokenParams<'_>,
    http_client: &Client,
) -> Result<(String, String), Error> {
    let token_url = format!(
        "{base_url}/realms/{realm}/protocol/openid-connect/token",
        base_url = base_url,
        realm = realm
    );
    let params = [
        ("grant_type", "authorization_code"),
        ("code", token_params.code),
        ("client_id", token_params.client_id),
        ("client_secret", token_params.client_secret),
        ("redirect_uri", token_params.redirect_uri),
    ];

    let res = http_client.post(&token_url).form(&params).send().await?;

    let res_json = res.json::<TokenResponse>().await?;
    return Ok((res_json.access_token, res_json.refresh_token));
}
