use parking_lot::Mutex;
use std::{collections::BTreeMap, fs, sync::Arc};
use tera::{Context, Tera};
use time::macros::format_description;
use time::OffsetDateTime;
use walker_extras::visitors::SendVisitor;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, serde::Deserialize, serde::Serialize)]
pub enum Phase {
    Retrieval,
    Validation,
    Upload,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, serde::Deserialize, serde::Serialize)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Report {
    #[serde(with = "time::serde::iso8601")]
    pub start_date: OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    pub end_date: OffsetDateTime,

    #[serde(default)]
    pub numer_of_items: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub messages: BTreeMap<Phase, BTreeMap<String, Vec<Message>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Message {
    pub severity: Severity,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct ReportBuilder {
    report: Report,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            report: Report {
                start_date: OffsetDateTime::now_utc(),
                end_date: OffsetDateTime::now_utc(),
                numer_of_items: 0,
                messages: Default::default(),
            },
        }
    }

    pub fn tick(&mut self) {
        self.report.numer_of_items += 1;
    }

    pub fn add_error(&mut self, phase: Phase, file: impl Into<String>, severity: Severity, message: impl Into<String>) {
        let file = file.into();
        let message = message.into();

        self.report
            .messages
            .entry(phase)
            .or_default()
            .entry(file)
            .or_default()
            .push(Message { severity, message });
    }

    pub fn build(mut self) -> Report {
        self.report.end_date = OffsetDateTime::now_utc();
        self.report
    }
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReportVisitor {
    pub report: Arc<Mutex<ReportBuilder>>,
    pub next: SendVisitor,
}

impl ReportVisitor {
    pub fn new(report: Arc<Mutex<ReportBuilder>>, next: SendVisitor) -> Self {
        Self { report, next }
    }
}

/// Fail a scanner process.
#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    /// A critical error occurred, we don't even have a report.
    #[error(transparent)]
    Critical(#[from] anyhow::Error),
    /// A normal error occurred, we did capture some information in the report.
    #[error("{err}")]
    Normal {
        #[source]
        err: anyhow::Error,
        report: Report,
    },
}

pub trait SplitScannerError {
    /// Split a [`ScannerError`] into a result and a report, unless it was critical.
    fn split(self) -> anyhow::Result<(Report, anyhow::Result<()>)>;
}

impl SplitScannerError for Result<Report, ScannerError> {
    fn split(self) -> anyhow::Result<(Report, anyhow::Result<()>)> {
        match self {
            Ok(report) => Ok((report, Ok(()))),
            Err(ScannerError::Normal { err, report }) => Ok((report, Err(err))),
            Err(ScannerError::Critical(err)) => Err(err),
        }
    }
}

/// Handle the report
pub async fn handle_report(report: Report, option: ReportGenerateOption) -> anyhow::Result<()> {
    if report.messages.is_empty() {
        log::info!("This report contains no error messages and does not require the generation of an error report");
        return Ok(());
    }

    let path = option.report_out_path;

    let mut tera = Tera::default();
    let template_content = include_str!("../templates/report.html");
    tera.add_raw_template("report.html", template_content)?;

    let mut context = Context::new();
    let current_time = OffsetDateTime::now_utc();

    let report_type = option.report_type;
    context.insert("report", &report);
    context.insert("type", &report_type);

    let format = format_description!("[year]-[month]-[day]--[hour]-[minute]-[second]");
    let formatted_time = current_time.format(&format)?;
    context.insert("current_time", &formatted_time);
    let rendered_html = tera.render("report.html", &context)?;
    let out_put_html_path = format!("{path}/{report_type}/html/report-{formatted_time}.html");
    if let Some(parent) = std::path::Path::new(&out_put_html_path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_put_html_path, rendered_html)?;
    log::info!("Successfully generated the report file.");

    Ok(())
}

#[derive(Clone, Debug)]
pub struct ReportGenerateOption {
    pub report_type: String,
    pub report_out_path: String,
}

#[cfg(test)]
mod tests {
    use crate::report::ReportGenerateOption;
    use crate::report::{handle_report, Message, Phase, Report, ReportBuilder, Severity};

    fn create_report() -> Report {
        let mut report = ReportBuilder::new();
        report
            .report
            .messages
            .entry(Phase::Validation)
            .or_default()
            .entry("test1".to_string())
            .or_default()
            .push(Message {
                severity: Severity::Error,
                message: "test1 message one".to_string(),
            });

        report
            .report
            .messages
            .entry(Phase::Upload)
            .or_default()
            .entry("test2".to_string())
            .or_default()
            .push(Message {
                severity: Severity::Error,
                message: "test2 message two".to_string(),
            });

        report.report
    }

    #[tokio::test]
    async fn test_handle_report_without_env() {
        let rs = handle_report(
            create_report(),
            ReportGenerateOption {
                report_type: "SBOM".to_string(),
                report_out_path: "tmp/share/reports".to_string(),
            },
        )
        .await;
        assert!(rs.is_ok());
    }
}
