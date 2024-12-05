use std::process::ExitCode;
use std::sync::Arc;

use guac::client::GuacClient;
use reqwest::Url;

use collectorist_client::CollectoristClient;
use trustification_auth::auth::AuthConfigArguments;
use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_auth::client::{OpenIdTokenProviderConfigArguments, TokenProvider};
use trustification_auth::swagger_ui::{SwaggerUiOidc, SwaggerUiOidcConfig};
use trustification_common::tls::ClientConfig;
use trustification_infrastructure::app::http::HttpServerConfig;
use trustification_infrastructure::endpoint::{self, Endpoint, Exhort};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use v11y_client::V11yClient;

mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[arg(
        long = "collectorist-url", 
        env = "COLLECTORIST_URL",
        default_value_t = endpoint::Collectorist::url()
    )]
    pub(crate) collectorist_url: Url,

    #[arg(
        long = "guac-url", 
        env = "GUAC_URL",
        default_value_t = endpoint::GuacGraphQl::url()
    )]
    pub(crate) guac_graphql_url: Url,

    #[arg(
        long = "v11y-url", 
        env = "V11Y_URL",
        default_value_t = endpoint::V11y::url()
    )]
    pub(crate) v11y_url: Url,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub(crate) oidc: OpenIdTokenProviderConfigArguments,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[command(flatten)]
    pub(crate) client: ClientConfig,

    #[command(flatten)]
    pub http: HttpServerConfig<Exhort>,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let (authn, authz) = self.auth.split(self.devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        let swagger_oidc: Option<Arc<SwaggerUiOidc>> =
            SwaggerUiOidc::from_devmode_or_config(self.devmode, self.swagger_ui_oidc)
                .await?
                .map(Arc::new);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        log::info!("collectorist URL: {}", self.collectorist_url);
        log::info!("guac URL: {}", self.guac_graphql_url);

        Infrastructure::from(self.infra)
            .run(
                "exhort-api",
                |_context| async { Ok(()) },
                |context| async move {
                    let provider = self.oidc.into_provider_or_devmode(self.devmode).await?;
                    let state = Self::configure(
                        &self.client,
                        self.collectorist_url,
                        self.v11y_url,
                        self.guac_graphql_url,
                        provider,
                    )?;

                    server::run(state, self.http, context, authenticator, authorizer, swagger_oidc).await
                },
            )
            .await?;
        Ok(ExitCode::SUCCESS)
    }

    fn configure<P>(
        client: &ClientConfig,
        collectorist_url: Url,
        v11y_url: Url,
        guac_graphql_url: Url,
        provider: P,
    ) -> anyhow::Result<Arc<AppState>>
    where
        P: TokenProvider + Clone + 'static,
    {
        let state = Arc::new(AppState {
            collectorist_client: CollectoristClient::new(
                client.build_client()?,
                "".to_string(),
                collectorist_url,
                provider.clone(),
            ),
            guac_client: GuacClient::new(guac_graphql_url.as_str()),
            v11y_client: V11yClient::new(client.build_client()?, v11y_url, provider),
        });
        Ok(state)
    }
}

pub struct AppState {
    collectorist_client: CollectoristClient,
    guac_client: GuacClient,
    v11y_client: V11yClient,
}
