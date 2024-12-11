use crate::db::Db;
use crate::{
    app_state::AppState,
    config,
    endpoints::{self, wellknown::endpoints::Endpoints},
    service::{collectorist::CollectoristService, guac::GuacService, v11y::V11yService},
    Run,
};
use actix_web::web;
use anyhow::Context;
use futures::future::select_all;
use std::future::Future;
use std::pin::Pin;
use std::{net::TcpListener, sync::Arc};
use trustification_analytics::Tracker;
use trustification_auth::{authenticator::Authenticator, authorizer::Authorizer, swagger_ui::SwaggerUiOidc};
use trustification_infrastructure::{app::http::HttpServerBuilder, MainContext};
use trustification_version::version;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub struct Server {
    run: Run,
}

impl Server {
    pub fn new(run: Run) -> Self {
        Self { run }
    }

    pub async fn run(self, context: MainContext<()>, listener: Option<TcpListener>) -> anyhow::Result<()> {
        let provider = self.run.oidc.into_provider_or_devmode(self.run.devmode).await?;
        let db_path = self.run.db_storage_base.unwrap_or_else(|| ".".into());
        let state = web::Data::new(AppState {
            client: self.run.client.build_client()?,
            bombastic: self.run.bombastic_url.clone(),
            vexination: self.run.vexination_url.clone(),
            exhort: self.run.exhort_url.clone(),
            provider: provider.clone(),
            db_storage: Db::new(db_path).await?,
        });

        let (authn, authz) = self.run.auth.split(self.run.devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_config(authn)
            .await
            .context("failed to create authenticator")?
            .map(Arc::new);
        let authorizer = Authorizer::new(authz);

        let swagger_oidc: Option<Arc<SwaggerUiOidc>> =
            SwaggerUiOidc::from_devmode_or_config(self.run.devmode, self.run.swagger_ui_oidc)
                .await?
                .map(Arc::new);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }
        if self.run.snyk_token.is_some() {
            log::info!("Snyk token is present");
        }

        let config_configurator = config::configurator(self.run.config, authenticator.clone()).await?;

        let crda_payload_limit = self.run.crda_payload_limit;

        let endpoints = Endpoints {
            vexination: String::from(self.run.vexination_url.as_str()),
            bombastic: String::from(self.run.bombastic_url.as_str()),
            collectorist: String::from(self.run.collectorist_url.as_str()),
            v11y: String::from(self.run.v11y_url.as_str()),
        };

        let guac = web::Data::new(GuacService::with_client(
            self.run.guac_url,
            self.run.client.build_client()?,
        ));

        let v11y = web::Data::new(V11yService::new(
            self.run.client.build_client()?,
            self.run.v11y_url,
            provider.clone(),
        ));
        let collectorist = web::Data::new(CollectoristService::new(
            self.run.client.build_client()?,
            self.run.collectorist_url,
            provider.clone(),
        ));

        let (tracker, flusher) = Tracker::new(self.run.analytics);
        let tracker = web::Data::from(tracker);

        let mut http = HttpServerBuilder::try_from(self.run.http)?
            .tracing(self.run.infra.tracing)
            .metrics(context.metrics.registry().clone(), "spog_api")
            .authorizer(authorizer.clone())
            .configure(move |svc| {
                svc.app_data(web::Data::new(state.clone()))
                    .app_data(state.clone())
                    .app_data(guac.clone())
                    .app_data(tracker.clone())
                    .app_data(v11y.clone())
                    .app_data(collectorist.clone())
                    .configure(endpoints::index::configure())
                    .configure(version::configurator(version!()))
                    .configure(endpoints::wellknown::endpoints::configurator(endpoints.clone()))
                    .configure(endpoints::sbom::configure(authenticator.clone()))
                    .configure(endpoints::advisory::configure(authenticator.clone()))
                    .configure(endpoints::cve::configure(authenticator.clone()))
                    .configure(endpoints::package::configure(authenticator.clone()))
                    .configure(endpoints::suggestion::configure(authenticator.clone()))
                    .configure(endpoints::dashboard::configure(
                        authenticator.clone(),
                        crda_payload_limit,
                    ))
                    .configure(config_configurator.clone())
                    .service({
                        let mut openapi = endpoints::ApiDoc::openapi();
                        let mut swagger = SwaggerUi::new("/swagger-ui/{_:.*}");

                        if let Some(swagger_ui_oidc) = &swagger_oidc {
                            swagger = swagger_ui_oidc.apply(swagger, &mut openapi);
                        }

                        swagger.url("/openapi.json", openapi)
                    });
            });

        if let Some(v) = listener {
            // override with provided listener
            http = http.listen(v);
        }

        let http = Box::pin(async move {
            http.run().await?;
            Ok(())
        }) as Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;

        let mut tasks = vec![http];

        tasks.extend(flusher);

        // run all tasks

        let (result, _index, _others) = select_all(tasks).await;

        // return

        result
    }
}
