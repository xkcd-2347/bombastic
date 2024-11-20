use crate::report::AdvisoryReportVisitor;
use csaf_walker::{
    discover::DiscoverConfig,
    retrieve::RetrievingVisitor,
    source::new_source,
    validation::ValidationVisitor,
    visitors::filter::{FilterConfig, FilteringVisitor},
    walker::Walker,
};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::time::MissedTickBehavior;
use tracing::{instrument, log};
use trustification_common_walker::report::{Report, ReportBuilder, ReportVisitor, ScannerError};
use url::Url;
use walker_common::{
    fetcher::FetcherOptions,
    sender::{self, provider::TokenProvider, HttpSenderOptions},
    since::Since,
    validate::ValidationOptions,
};

pub struct Options {
    pub source: String,
    pub target: Url,
    pub provider: Arc<dyn TokenProvider>,
    pub validation_date: Option<SystemTime>,
    pub required_prefixes: Vec<String>,
    pub ignore_distributions: Vec<String>,
    pub since_file: Option<PathBuf>,
    pub additional_root_certificates: Vec<PathBuf>,
    pub retries: usize,
    pub retry_delay: Option<Duration>,
}

pub struct Scanner {
    options: Options,
}

impl Scanner {
    pub fn new(options: Options) -> Self {
        Self { options }
    }

    pub async fn run(self, interval: Duration) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            if let Err(err) = self.run_once().await {
                log::warn!("Failed to perform sync: {err}");
            }
            interval.tick().await;
        }
    }

    #[instrument(skip(self))]
    pub async fn run_once(&self) -> Result<Report, ScannerError> {
        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let since = Since::new(None::<SystemTime>, self.options.since_file.clone(), Default::default())?;

        let source = new_source(
            DiscoverConfig {
                source: self.options.source.clone(),
                since: *since,
            },
            FetcherOptions::default().retries(self.options.retries),
        )
        .await?;

        let sender = sender::HttpSender::new(
            self.options.provider.clone(),
            HttpSenderOptions::new().additional_root_certificates(self.options.additional_root_certificates.clone()),
        )
        .await?;

        let mut storage = walker_extras::visitors::SendVisitor::new(self.options.target.clone(), sender)
            .retries(self.options.retries);
        storage.retry_delay = self.options.retry_delay;

        let validation = ValidationVisitor::new(AdvisoryReportVisitor(ReportVisitor::new(report.clone(), storage)))
            .with_options(ValidationOptions::new().validation_date(self.options.validation_date));

        let retriever = RetrievingVisitor::new(source.clone(), validation);

        let filtered = FilteringVisitor {
            visitor: retriever,
            config: FilterConfig::new()
                .ignored_distributions(self.options.ignore_distributions.clone())
                .only_prefixes(self.options.required_prefixes.clone()),
        };

        let walker = Walker::new(source.clone());
        walker
            .walk(filtered)
            .await
            // if the walker fails, we record the outcome as part of the report, but skip any
            // further processing, like storing the marker
            .map_err(|err| ScannerError::Normal {
                err: err.into(),
                report: report.lock().clone().build(),
            })?;

        since.store()?;

        // we're done and return the report
        Ok(match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build())
    }
}
