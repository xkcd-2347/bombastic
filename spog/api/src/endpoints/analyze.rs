use crate::analytics::{SbomType, ScanSbom};
use actix_web::{
    body::BoxBody,
    web::{self, PayloadConfig, ServiceConfig},
    HttpResponse, ResponseError,
};
use bombastic_model::prelude::SBOM;
use bytes::Bytes;
use futures::Stream;
use http::{header, StatusCode};
use std::time::Duration;
use tracing::instrument;
use trustification_analytics::Tracker;
use trustification_common::error::ErrorInformation;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    Data(#[from] bombastic_model::data::Error),
    #[error("backend error: {0}")]
    Crda(String),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Error::Url(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "UrlParseError".into(),
                message: "Failed to build request URL".into(),
                details: err.to_string(),
            }),
            Error::Request(err) => HttpResponse::BadGateway().json(ErrorInformation {
                error: "ClientRequestError".into(),
                message: "Failed to contact the analytics server".into(),
                details: err.to_string(),
            }),
            Error::Data(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "InvalidSBOMFormat".into(),
                message: "Unable to parse SBOM".into(),
                details: err.to_string(),
            }),
            Error::Crda(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "InvalidSBOMContent".into(),
                message: "Unable to process SBOM".into(),
                details: err.to_string(),
            }),
        }
    }
}

static RHDA_SOURCE_HEADER: header::HeaderName = header::HeaderName::from_static("rhda-source");
const RHDA_SOURCE_VALUE: &str = "trustification";
// TODO: when having consent, forward the user ID
#[allow(unused)]
static RHDA_TOKEN_HEADER: header::HeaderName = header::HeaderName::from_static("rhda-token");
static RHDA_OPERATION_TYPE_HEADER: header::HeaderName = header::HeaderName::from_static("rhda-operation-type");
const RHDA_OPERATION_TYPE_VALUE: &str = "stack-analysis";
static EXHORT_SNYK_TOKEN: header::HeaderName = header::HeaderName::from_static("ex-snyk-token");

#[derive(Clone)]
pub struct CrdaClient {
    client: reqwest::Client,
    url: Url,
    snyk_token: Option<String>,
}

impl CrdaClient {
    pub fn new(url: Url, snyk_token: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60 * 3))
            .build()
            .expect("Could not create the crda client");

        Self {
            client,
            url,
            snyk_token,
        }
    }

    #[instrument(skip(self, sbom), fields(sbom_size = sbom.as_bytes().map(|b|b.len())), err)]
    pub async fn analyze(
        &self,
        sbom: reqwest::Body,
        content_type: &str,
    ) -> Result<impl Stream<Item = reqwest::Result<Bytes>>, Error> {
        let mut req = self
            .client
            .post(self.url.clone())
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::ACCEPT, "text/html")
            .header(&RHDA_SOURCE_HEADER, RHDA_SOURCE_VALUE)
            .header(&RHDA_OPERATION_TYPE_HEADER, RHDA_OPERATION_TYPE_VALUE);

        if let Some(snyk_token) = &self.snyk_token {
            req = req.header(&EXHORT_SNYK_TOKEN, snyk_token);
        }

        let res = req.body(sbom).send().await?;

        log::info!("CRDA status code: {}", res.status());

        if res.status().is_client_error() {
            let message = res.text().await?;
            log::info!("CRDA error: {message}");
            Err(Error::Crda(message))
        } else {
            Ok(res.error_for_status()?.bytes_stream())
        }
    }
}

pub(crate) fn configure(payload_limit: usize) -> impl FnOnce(&mut ServiceConfig) {
    move |config: &mut ServiceConfig| {
        config.service(
            web::resource("/api/v1/analyze/report")
                .app_data(PayloadConfig::new(payload_limit))
                .to(report),
        );
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/analyze/report",
    responses(
        (status = OK, description = "Generated CRDA report", body = String),
        (status = 400, description = "Invalid SBOM format", body = String),
        (status = 502, description = "Failed to communicate with CRDA backend", body = String),
    )
)]
async fn report(
    data: Bytes,
    crda: web::Data<CrdaClient>,
    tracker: web::Data<Tracker>,
) -> actix_web::Result<HttpResponse> {
    Ok(run_report(data, &crda, &tracker).await?)
}

#[instrument(skip_all, fields(data_len=data.len()), err)]
async fn run_report(data: Bytes, crda: &CrdaClient, tracker: &Tracker) -> Result<HttpResponse, Error> {
    let sbom = SBOM::parse(&data)?;

    let (r#type, content_type) = match &sbom {
        SBOM::SPDX(_) => (SbomType::Spdx, "application/vnd.spdx+json"),
        SBOM::CycloneDX(_) => (SbomType::CycloneDx, "application/vnd.cyclonedx+json"),
    };

    let report = crda.analyze(data.into(), content_type).await;

    let status_code = match &report {
        Err(Error::Request(err)) => err.status(),
        _ => None,
    };

    tracker
        .track(ScanSbom {
            r#type,
            status_code: status_code.map(|s| StatusCode::as_u16(&s)),
        })
        .await;

    Ok(HttpResponse::Ok().content_type("text/html").streaming(report?))
}
