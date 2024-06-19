use reqwest::{Client, Error};
use serde::Deserialize;
use std::fmt;

pub fn get_auth_url(base_url: &str, realm: &str, client_id: &str, redirect_uri: &str) -> String {
    format!("{base_url}/realms/{realm}/protocol/openid-connect/auth?response_type=code&scope=openid&client_id={client_id}&redirect_uri={redirect_uri}", base_url=base_url, realm=realm, client_id=client_id, redirect_uri=redirect_uri)
}

pub struct ObtainTokensParams<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
}

#[derive(Deserialize)]
pub struct TokensResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub enum ObtainTokensError {
    SendingRequestError(Error),
    InvalidRequestError(Error),
    InvalidResponseError(Error),
}

impl fmt::Display for ObtainTokensError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ObtainTokensError::SendingRequestError(err)
            | ObtainTokensError::InvalidRequestError(err)
            | ObtainTokensError::InvalidResponseError(err) => write!(f, "{}", err),
        }
    }
}

pub async fn obtain_tokens(
    base_url: &str,
    realm: &str,
    params: ObtainTokensParams<'_>,
    http_client: &Client,
) -> Result<TokensResponse, ObtainTokensError> {
    let url = format!(
        "{base_url}/realms/{realm}/protocol/openid-connect/token",
        base_url = base_url,
        realm = realm
    );
    let params = [
        ("grant_type", "authorization_code"),
        ("code", params.code),
        ("client_id", params.client_id),
        ("client_secret", params.client_secret),
        ("redirect_uri", params.redirect_uri),
    ];

    let res = http_client
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(ObtainTokensError::SendingRequestError)?;

    if res.status().is_client_error() {
        return Err(ObtainTokensError::InvalidRequestError(
            res.error_for_status().err().unwrap(),
        ));
    }
    res.error_for_status_ref()
        .map_err(ObtainTokensError::InvalidResponseError)?;
    let tokens = res
        .json::<TokensResponse>()
        .await
        .map_err(ObtainTokensError::InvalidResponseError)?;
    Ok(tokens)
}

#[derive(Deserialize)]
pub struct JWKSResponse {
    keys: Vec<JWKResponse>,
}

#[derive(Deserialize)]
pub struct JWKResponse {
    pub kid: String,
    pub alg: String,
    pub e: String,
    pub n: String,
}

pub enum RetrievingJWKError {
    SendingRequestError(Error),
    InvalidResponseError(Error),
    JWKNotFoundError(String),
}

impl fmt::Display for RetrievingJWKError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RetrievingJWKError::SendingRequestError(err)
            | RetrievingJWKError::InvalidResponseError(err) => write!(f, "{}", err),
            RetrievingJWKError::JWKNotFoundError(kid) => {
                write!(f, "Not found JWK with the associated kid {}", kid)
            }
        }
    }
}

pub async fn get_jwk(
    base_url: &str,
    realm: &str,
    kid: &str,
    http_client: &Client,
) -> Result<JWKResponse, RetrievingJWKError> {
    let url = format!(
        "{base_url}/realms/{realm}/protocol/openid-connect/certs",
        base_url = base_url,
        realm = realm
    );

    let res = http_client
        .get(&url)
        .send()
        .await
        .map_err(RetrievingJWKError::SendingRequestError)?
        .error_for_status()
        .map_err(RetrievingJWKError::InvalidResponseError)?;

    let jwks = res
        .json::<JWKSResponse>()
        .await
        .map_err(RetrievingJWKError::InvalidResponseError)?;
    jwks.keys
        .into_iter()
        .find(|key| key.kid == kid)
        .ok_or_else(|| RetrievingJWKError::JWKNotFoundError(kid.to_string()))
}

pub struct RefreshTokenParams<'a> {
    pub refresh_token: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
}

pub enum RefreshTokenError {
    SendingRequestError(Error),
    InvalidRequestError(Error),
    InvalidResponseError(Error),
}

impl fmt::Display for RefreshTokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RefreshTokenError::SendingRequestError(err)
            | RefreshTokenError::InvalidRequestError(err)
            | RefreshTokenError::InvalidResponseError(err) => write!(f, "{}", err),
        }
    }
}

pub async fn refresh_token(
    base_url: &str,
    realm: &str,
    params: RefreshTokenParams<'_>,
    http_client: &Client,
) -> Result<TokensResponse, RefreshTokenError> {
    let url = format!(
        "{base_url}/realms/{realm}/protocol/openid-connect/token",
        base_url = base_url,
        realm = realm
    );
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", params.refresh_token),
        ("client_id", params.client_id),
        ("client_secret", params.client_secret),
    ];

    let res = http_client
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(RefreshTokenError::SendingRequestError)?;

    if res.status().is_client_error() {
        return Err(RefreshTokenError::InvalidRequestError(
            res.error_for_status().err().unwrap(),
        ));
    }
    res.error_for_status_ref()
        .map_err(RefreshTokenError::InvalidResponseError)?;
    let tokens = res
        .json::<TokensResponse>()
        .await
        .map_err(RefreshTokenError::InvalidResponseError)?;
    Ok(tokens)
}
