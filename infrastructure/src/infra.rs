use std::sync::Arc;
use std::{future::Future, pin::Pin};

use actix_web::web::ServiceConfig;
use actix_web::{http::uri::Builder, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::Context;
use futures::future::select_all;
use prometheus::{Registry, TextEncoder};
use tokio::signal;

use crate::tracing::{init_tracing, Tracing};

use crate::health::{Checks, HealthChecks};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

const DEFAULT_BIND_ADDR: &str = "localhost:9010";

/// Infrastructure
#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE", next_help_heading = "Infrastructure")]
pub struct InfrastructureConfig {
    /// Enable the infrastructure endpoint
    #[arg(env, long)]
    pub infrastructure_enabled: bool,
    /// Bind addresses of the infrastructure endpoint
    #[arg(long, env, default_value_t = DEFAULT_BIND_ADDR.into())]
    pub infrastructure_bind: String,
    /// Number of workers
    #[arg(long, env, default_value = "1")]
    pub infrastructure_workers: usize,
    /// Enable tracing
    #[arg(long, env, default_value_t = Tracing::Disabled)]
    pub tracing: Tracing,
}

impl Default for InfrastructureConfig {
    fn default() -> Self {
        Self {
            infrastructure_enabled: false,
            infrastructure_bind: DEFAULT_BIND_ADDR.into(),
            infrastructure_workers: 1,
            tracing: Tracing::Disabled,
        }
    }
}

pub struct InitContext {
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthChecks>,
}

pub struct MainContext<T> {
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthChecks>,
    pub init_data: T,
}

pub async fn index(req: HttpRequest) -> HttpResponse {
    let conn = req.connection_info();

    let apis = ["/health/live", "/health/ready", "/health/startup", "/metrics"]
        .into_iter()
        .filter_map(|api| {
            Builder::new()
                .authority(conn.host())
                .scheme(conn.scheme())
                .path_and_query(api)
                .build()
                .ok()
                .map(|uri| uri.to_string())
        })
        .collect::<Vec<_>>();

    HttpResponse::Ok().json(apis)
}

async fn startup(health: web::Data<HealthChecks>) -> impl Responder {
    run_checks(&health.startup).await
}

async fn liveness(health: web::Data<HealthChecks>) -> impl Responder {
    run_checks(&health.liveness).await
}

async fn readiness(health: web::Data<HealthChecks>) -> impl Responder {
    run_checks(&health.readiness).await
}

async fn run_checks(checks: &Checks) -> impl Responder {
    let checks = checks.run().await;

    let mut result = match checks.all_up() {
        true => HttpResponse::Ok(),
        false => HttpResponse::InternalServerError(),
    };

    result.json(checks.results)
}

async fn metrics(metrics: web::Data<Arc<Metrics>>) -> HttpResponse {
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry().gather();
    match encoder.encode_to_string(&metric_families) {
        Ok(data) => HttpResponse::Ok().content_type("text/plain").body(data),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error retrieving metrics: {:?}", e)),
    }
}

#[derive(Default)]
pub struct Infrastructure {
    config: InfrastructureConfig,
    metrics: Arc<Metrics>,
    health: Arc<HealthChecks>,
}

impl From<InfrastructureConfig> for Infrastructure {
    fn from(config: InfrastructureConfig) -> Self {
        Self {
            config,
            metrics: Default::default(),
            health: Default::default(),
        }
    }
}

impl Infrastructure {
    /// create a new instance, with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start(self) -> anyhow::Result<InfrastructureRunner> {
        Ok(InfrastructureRunner {
            runner: Box::pin(self.start_internal(|_| {}).await?),
        })
    }

    async fn start_internal(
        self,
        configurator: impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static,
    ) -> anyhow::Result<Pin<Box<dyn Future<Output = anyhow::Result<()>>>>> {
        if !self.config.infrastructure_enabled {
            log::info!("Infrastructure endpoint is disabled");
            return Ok(Box::pin(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await
                }
            }));
        }

        log::info!("Setting up infrastructure endpoint");

        let mut http = HttpServer::new(move || {
            let metrics_registry = self.metrics.clone();
            let health = self.health.clone();
            let configurator = configurator.clone();
            App::new()
                .wrap(Logger::default())
                .app_data(web::Data::new(metrics_registry))
                .app_data(web::Data::from(health))
                .service(web::resource("/").to(index))
                .service(
                    web::scope("/health")
                        .service(web::resource("/live").to(liveness))
                        .service(web::resource("/ready").to(readiness))
                        .service(web::resource("/startup").to(startup)),
                )
                .service(web::resource("/metrics").to(metrics))
                .configure(|c| configurator(c))
        });

        if self.config.infrastructure_workers > 0 {
            http = http.workers(self.config.infrastructure_workers);
        }

        http = http
            .bind(self.config.infrastructure_bind)
            .context("Failed to bind infrastructure endpoint")?;

        Ok(Box::pin(async move {
            log::info!("Running infrastructure endpoint on:");
            for (addr, scheme) in http.addrs_with_scheme() {
                log::info!("   {scheme}://{addr}");
            }
            http.run().await.context("Failed to run infrastructure endpoint")?;
            Ok::<_, anyhow::Error>(())
        }))
    }

    pub async fn run_with_config<I, IFut, M, MFut, D>(
        self,
        id: &str,
        init: I,
        main: M,
        configurator: impl FnOnce(&mut ServiceConfig) + Clone + Send + 'static,
    ) -> anyhow::Result<()>
    where
        I: FnOnce(InitContext) -> IFut,
        IFut: Future<Output = anyhow::Result<D>>,
        M: FnOnce(MainContext<D>) -> MFut,
        MFut: Future<Output = anyhow::Result<()>>,
    {
        let init_data = init(InitContext {
            metrics: self.metrics.clone(),
            health: self.health.clone(),
        })
        .await?;

        init_tracing(id, self.config.tracing);
        let main = Box::pin(main(MainContext {
            init_data,
            metrics: self.metrics.clone(),
            health: self.health.clone(),
        })) as Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;
        let runner = Box::pin(self.start_internal(configurator).await?);
        let sigint = Box::pin(async { signal::ctrl_c().await.context("termination failed") });

        #[allow(unused_mut)]
        let mut tasks = vec![runner, main, sigint];

        #[cfg(unix)]
        {
            let sigterm = Box::pin(async {
                signal(SignalKind::terminate())?.recv().await;
                Ok(())
            });
            tasks.push(sigterm);
        }

        let (result, _index, _others) = select_all(tasks).await;
        result
    }

    /// Run the main application with a set of infrastructure services.
    ///
    /// If configured, this will enable infrastructure services, such as metrics and health checks.
    /// It will then run the `main` application until it exits. The `init` function is guaranteed to
    /// the executed before the `main` function, allowing for some initialization.
    pub async fn run<I, IFut, M, MFut, D>(self, id: &str, init: I, main: M) -> anyhow::Result<()>
    where
        I: FnOnce(InitContext) -> IFut,
        IFut: Future<Output = anyhow::Result<D>>,
        M: FnOnce(MainContext<D>) -> MFut,
        MFut: Future<Output = anyhow::Result<()>>,
    {
        self.run_with_config(id, init, main, |_| {}).await
    }
}

#[derive(Default)]
pub struct Metrics {
    registry: Registry,
}

impl Metrics {
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

pub struct InfrastructureRunner {
    runner: Pin<Box<dyn Future<Output = anyhow::Result<()>>>>,
}

impl InfrastructureRunner {
    pub async fn run(self) -> anyhow::Result<()> {
        self.runner.await
    }
}
