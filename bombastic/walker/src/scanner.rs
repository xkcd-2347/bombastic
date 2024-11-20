use crate::{processing::ProcessVisitor, report::SbomReportVisitor};
use parking_lot::Mutex;
use sbom_walker::{
    discover::DiscoverConfig, model::metadata::Key, retrieve::RetrievingVisitor, source::new_source,
    validation::ValidationVisitor, walker::Walker,
};
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
    pub keys: Vec<Key>,
    pub provider: Arc<dyn TokenProvider>,
    pub validation_date: Option<SystemTime>,
    pub fix_licenses: bool,
    pub since_file: Option<PathBuf>,
    pub retries: usize,
    pub retry_delay: Option<Duration>,
    pub additional_root_certificates: Vec<PathBuf>,
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
                keys: self.options.keys.clone(),
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

        let process = ProcessVisitor {
            enabled: self.options.fix_licenses,
            next: SbomReportVisitor(ReportVisitor::new(report.clone(), storage)),
            report: report.clone(),
        };

        let validation = ValidationVisitor::new(process)
            .with_options(ValidationOptions::new().validation_date(self.options.validation_date));

        let walker = Walker::new(source.clone());
        walker
            .walk(RetrievingVisitor::new(source.clone(), validation))
            .await
            // if the walker fails, we record the outcome as part of the report, but skip any
            // further processing, like storing the marker
            .map_err(|err| ScannerError::Normal {
                err: err.into(),
                report: report.lock().clone().build(),
            })?;

        // if we fail to store the marker, we fail altogether
        since.store()?;

        // we're done and return the report
        Ok(match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build())
    }
}
