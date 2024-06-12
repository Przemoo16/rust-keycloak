use reqwest::{Client, Error};
use serde::Deserialize;
use std::fmt;

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
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub enum TokenExchangeError {
    SendingRequestError(Error),
    InvalidRequestError(Error),
    InvalidResponseError(Error),
}

impl fmt::Display for TokenExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TokenExchangeError::SendingRequestError(err)
            | TokenExchangeError::InvalidRequestError(err)
            | TokenExchangeError::InvalidResponseError(err) => write!(f, "{}", err),
        }
    }
}

pub async fn exchange_code_for_token(
    base_url: &str,
    realm: &str,
    token_params: TokenParams<'_>,
    http_client: &Client,
) -> Result<TokenResponse, TokenExchangeError> {
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

    let res = http_client
        .post(&token_url)
        .form(&params)
        .send()
        .await
        .map_err(TokenExchangeError::SendingRequestError)?;

    if res.status().is_client_error() {
        return Err(TokenExchangeError::InvalidRequestError(
            res.error_for_status().err().unwrap(),
        ));
    }

    let token_response = res
        .json::<TokenResponse>()
        .await
        .map_err(TokenExchangeError::InvalidResponseError)?;
    return Ok(token_response);
}
