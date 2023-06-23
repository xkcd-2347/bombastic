use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use http::StatusCode;
use spog_model::search;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{advisory, sbom, Run};

pub struct Server {
    run: Run,
}

#[derive(OpenApi)]
#[openapi(
        paths(
            sbom::get,
            sbom::search,
            advisory::get,
            advisory::search,
            version::get,
            //vulnerability::search,
        ),
        components(
            //schemas(search::PackageSummary, search::VulnSummary, search::SearchResult<Vec<search::PackageSummary>>)
            schemas(search::PackageSummary, search::SearchResult<Vec<search::PackageSummary>>, spog_model::Version)
        ),
        tags(
            (name = "package", description = "Package endpoints"),
            (name = "advisory", description = "Advisory endpoints"),
          //  (name = "vulnerability", description = "Vulnerability endpoints"),
        ),
    )]
pub struct ApiDoc;

impl Server {
    pub fn new(run: Run) -> Self {
        Self { run }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let openapi = ApiDoc::openapi();

        let state = configure(&self.run)?;

        HttpServer::new(move || {
            let state = state.clone();
            let cors = Cors::default()
                .send_wildcard()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);

            App::new()
                .wrap(Logger::default())
                .wrap(cors)
                .app_data(web::Data::new(state))
                .configure(crate::sbom::configure())
                .configure(crate::advisory::configure())
                .configure(crate::version::configure())
                //.configure(crate::vulnerability::configure())
                .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
        })
        .bind((self.run.bind, self.run.port))?
        .run()
        .await?;
        Ok(())
    }
}

pub struct AppState {
    client: reqwest::Client,
    pub bombastic: reqwest::Url,
    pub vexination: reqwest::Url,
}

impl AppState {
    pub async fn get_sbom(
        &self,
        id: &str,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, anyhow::Error> {
        let url = self.bombastic.join("/api/v1/sbom")?;
        let response = self.client.get(url).query(&[("id", id)]).send().await?;
        if response.status() == StatusCode::OK {
            Ok(response.bytes_stream())
        } else {
            Err(anyhow::anyhow!(
                "Error querying bombastic service: {:?}",
                response.status()
            ))
        }
    }

    pub async fn search_sbom(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
    ) -> Result<bombastic_model::search::SearchResult, anyhow::Error> {
        let url = self.bombastic.join("/api/v1/sbom/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.json::<bombastic_model::prelude::SearchResult>().await?)
        } else {
            Err(anyhow::anyhow!(
                "Error querying bombastic service: {:?}",
                response.status()
            ))
        }
    }

    pub async fn get_vex(
        &self,
        id: &str,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, anyhow::Error> {
        let url = self.vexination.join("/api/v1/vex")?;
        let response = self.client.get(url).query(&[("advisory", id)]).send().await?;
        if response.status() == StatusCode::OK {
            Ok(response.bytes_stream())
        } else {
            Err(anyhow::anyhow!(
                "Error querying bombastic service: {:?}",
                response.status()
            ))
        }
    }

    pub async fn search_vex(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
    ) -> Result<vexination_model::search::SearchResult, anyhow::Error> {
        let url = self.vexination.join("/api/v1/vex/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.json::<vexination_model::prelude::SearchResult>().await?)
        } else {
            Err(anyhow::anyhow!(
                "Error querying vexination service: {:?}",
                response.status()
            ))
        }
    }
}

pub type SharedState = Arc<AppState>;

pub(crate) fn configure(run: &Run) -> anyhow::Result<Arc<AppState>> {
    let state = Arc::new(AppState {
        client: reqwest::Client::new(),
        bombastic: run.bombastic_url.clone(),
        vexination: run.vexination_url.clone(),
    });
    Ok(state)
}
