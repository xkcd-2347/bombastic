use super::{
    super::{error::Error, Expires},
    {Credentials, TokenProvider},
};
use crate::devmode;
use anyhow::Context;
use core::fmt::{self, Debug, Formatter};
use std::time::Duration;
use std::{ops::Deref, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, clap::Args)]
#[command(next_help_heading = "OIDC client configuration")]
pub struct OpenIdTokenProviderConfigArguments {
    #[arg(
        id = "oidc_client_id",
        long = "oidc-client-id",
        env = "OIDC_PROVIDER_CLIENT_ID",
        requires("OpenIdTokenProviderConfigArguments")
    )]
    pub client_id: Option<String>,
    #[arg(
        id = "oidc_client_secret",
        long = "oidc-client-secret",
        env = "OIDC_PROVIDER_CLIENT_SECRET",
        requires("OpenIdTokenProviderConfigArguments")
    )]
    pub client_secret: Option<String>,
    #[arg(
        id = "oidc_issuer_url",
        long = "oidc-issuer-url",
        env = "OIDC_PROVIDER_ISSUER_URL",
        requires("OpenIdTokenProviderConfigArguments")
    )]
    pub issuer_url: Option<String>,
    #[arg(
        id = "oidc_refresh_before",
        long = "oidc-refresh-before",
        env = "OIDC_PROVIDER_REFRESH_BEFORE",
        default_value = "30s"
    )]
    pub refresh_before: humantime::Duration,
}

impl OpenIdTokenProviderConfigArguments {
    pub fn devmode() -> OpenIdTokenProviderConfigArguments {
        Self {
            issuer_url: Some(devmode::issuer_url()),
            client_id: Some(devmode::SERVICE_CLIENT_ID.to_string()),
            client_secret: Some(devmode::SSO_CLIENT_SECRET.to_string()),
            refresh_before: Duration::from_secs(30).into(),
        }
    }
}

impl OpenIdTokenProviderConfigArguments {
    pub async fn into_provider(self) -> anyhow::Result<Arc<dyn TokenProvider>> {
        OpenIdTokenProviderConfig::new_provider(OpenIdTokenProviderConfig::from_args(self)).await
    }

    pub async fn into_provider_or_devmode(self, devmode: bool) -> anyhow::Result<Arc<dyn TokenProvider>> {
        let config = match devmode {
            true => Some(OpenIdTokenProviderConfig::devmode()),
            false => OpenIdTokenProviderConfig::from_args(self),
        };

        OpenIdTokenProviderConfig::new_provider(config).await
    }
}

#[derive(Clone, Debug, PartialEq, Eq, clap::Args)]
pub struct OpenIdTokenProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub refresh_before: humantime::Duration,
}

impl OpenIdTokenProviderConfig {
    pub fn devmode() -> Self {
        Self {
            issuer_url: devmode::issuer_url(),
            client_id: devmode::SERVICE_CLIENT_ID.to_string(),
            client_secret: devmode::SSO_CLIENT_SECRET.to_string(),
            refresh_before: Duration::from_secs(30).into(),
        }
    }

    pub async fn new_provider(config: Option<Self>) -> anyhow::Result<Arc<dyn TokenProvider>> {
        Ok(match config {
            Some(config) => Arc::new(OpenIdTokenProvider::with_config(config).await?),
            None => Arc::new(()),
        })
    }

    pub fn from_args(arguments: OpenIdTokenProviderConfigArguments) -> Option<Self> {
        match (arguments.client_id, arguments.client_secret, arguments.issuer_url) {
            (Some(client_id), Some(client_secret), Some(issuer_url)) => Some(OpenIdTokenProviderConfig {
                client_id,
                client_secret,
                issuer_url,
                refresh_before: arguments.refresh_before,
            }),
            _ => None,
        }
    }
}

impl From<OpenIdTokenProviderConfigArguments> for Option<OpenIdTokenProviderConfig> {
    fn from(value: OpenIdTokenProviderConfigArguments) -> Self {
        OpenIdTokenProviderConfig::from_args(value)
    }
}

/// A provider which provides access tokens for clients.
#[derive(Clone)]
pub struct OpenIdTokenProvider {
    client: Arc<openid::Client>,
    current_token: Arc<RwLock<Option<openid::Bearer>>>,
    refresh_before: chrono::Duration,
}

impl Debug for OpenIdTokenProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenProvider")
            .field(
                "client",
                &format!("{} / {:?}", self.client.client_id, self.client.http_client),
            )
            .field("current_token", &"...")
            .finish()
    }
}

impl OpenIdTokenProvider {
    /// Create a new provider using the provided client.
    pub fn new(client: openid::Client, refresh_before: chrono::Duration) -> Self {
        Self {
            client: Arc::new(client),
            current_token: Arc::new(RwLock::new(None)),
            refresh_before,
        }
    }

    pub async fn with_config(config: OpenIdTokenProviderConfig) -> anyhow::Result<Self> {
        let issuer = Url::parse(&config.issuer_url).context("Parse issuer URL")?;
        let client = openid::Client::discover(config.client_id, config.client_secret, None, issuer)
            .await
            .context("Discover OIDC client")?;
        Ok(Self::new(
            client,
            chrono::Duration::from_std(config.refresh_before.into())?,
        ))
    }

    /// return a fresh token, this may be an existing (non-expired) token
    /// a newly refreshed token.
    pub async fn provide_token(&self) -> Result<openid::Bearer, openid::error::Error> {
        match self.current_token.read().await.deref() {
            Some(token) if !token.expires_before(self.refresh_before) => {
                log::debug!("Token still valid");
                return Ok(token.clone());
            }
            _ => {}
        }

        // fetch fresh token after releasing the read lock

        self.fetch_fresh_token().await
    }

    async fn fetch_fresh_token(&self) -> Result<openid::Bearer, openid::error::Error> {
        log::debug!("Fetching fresh token...");

        let mut lock = self.current_token.write().await;

        match lock.deref() {
            // check if someone else refreshed the token in the meantime
            Some(token) if !token.expires_before(self.refresh_before) => {
                log::debug!("Token already got refreshed");
                return Ok(token.clone());
            }
            _ => {}
        }

        // we hold the write-lock now, and can perform the refresh operation

        let next_token = match lock.take() {
            // if we don't have any token, fetch an initial one
            None => {
                log::debug!("Fetching initial token... ");
                self.initial_token().await?
            }
            // if we have an expired one, refresh it
            Some(current_token) => {
                log::debug!("Refreshing token ... ");
                match current_token.refresh_token.is_some() {
                    true => self.client.refresh_token(current_token, None).await?,
                    false => self.initial_token().await?,
                }
            }
        };

        log::debug!("Next token: {:?}", next_token);

        lock.replace(next_token.clone());

        // done

        Ok(next_token)
    }

    async fn initial_token(&self) -> Result<openid::Bearer, openid::error::Error> {
        Ok(self.client.request_token_using_client_credentials(None).await?)
    }
}

#[async_trait::async_trait]
impl TokenProvider for OpenIdTokenProvider {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(self
            .provide_token()
            .await
            .map(|token| Some(Credentials::Bearer(token.access_token)))?)
    }
}
