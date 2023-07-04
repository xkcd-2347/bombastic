use prometheus::{opts, register_int_counter_with_registry, IntCounter, Registry};
use reqwest::Client;
use url::Url;

#[derive(Clone)]
struct Metrics {
    satisfied_total: IntCounter,
    not_satisfied_total: IntCounter,
}

impl Metrics {
    fn register(registry: &Registry) -> Result<Self, Error> {
        let satisfied_total = register_int_counter_with_registry!(
            opts!("policy_satisfied", "Total number of policies checks satisfied"),
            registry
        )?;

        let not_satisfied_total = register_int_counter_with_registry!(
            opts!("policy_not_satisfied", "Total number of policies checks not satisfied"),
            registry
        )?;

        Ok(Metrics {
            satisfied_total,
            not_satisfied_total,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("policy not satisfied: {0}")]
    NotSatisfied(String),

    #[error("policy request failed {0}")]
    RequestFailed(String),

    #[error("prometheus error {0}")]
    Prometheus(prometheus::Error),
}

impl From<prometheus::Error> for Error {
    fn from(e: prometheus::Error) -> Self {
        Self::Prometheus(e)
    }
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct PolicyConfig {
    /// URL to policy endpoint for policy checks
    #[arg(long = "policy-url")]
    pub url: Option<Url>,
}

impl PolicyConfig {
    pub fn create(&self, registry: &Registry) -> Result<PolicyClient, Error> {
        Ok(PolicyClient::new(self.url.clone(), registry)?)
    }
}

pub struct PolicyClient {
    url: Option<Url>,
    client: Client,
    metrics: Metrics,
}

impl PolicyClient {
    pub fn new(url: Option<Url>, registry: &Registry) -> Result<Self, Error> {
        Ok(Self {
            url,
            client: reqwest::Client::new(),
            metrics: Metrics::register(registry)?,
        })
    }
    pub async fn check(&self, input: &[u8]) -> Result<(), Error> {
        if let Some(url) = &self.url {
            Ok(())
        } else {
            // No policy endpoint configured
            self.metrics.satisfied_total.inc();
            Ok(())
        }
    }
}
