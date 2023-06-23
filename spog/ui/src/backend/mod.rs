// pub mod data;

pub mod data {
    pub use spog_model::prelude::*;
}

mod api;
mod pkg;
mod sbom;
mod vuln;

pub use api::*;
pub use pkg::*;
pub use sbom::*;
use url::{ParseError, Url};
pub use vuln::*;
use yew::html::IntoPropValue;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub endpoints: Endpoints,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Endpoints {
    pub url: Url,
}

impl Endpoints {
    pub fn get(&self, endpoint: Endpoint) -> &Url {
        match endpoint {
            Endpoint::Api => &self.url,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Endpoint {
    Api,
}

impl Backend {
    pub fn join(&self, endpoint: Endpoint, input: &str) -> Result<Url, Error> {
        Ok(self.endpoints.get(endpoint).join(input)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to parse backend URL: {0}")]
    Url(#[from] ParseError),
    #[error("Failed to request: {0}")]
    Request(#[from] reqwest::Error),
}

impl IntoPropValue<String> for Error {
    fn into_prop_value(self) -> String {
        self.to_string()
    }
}

impl IntoPropValue<String> for &Error {
    fn into_prop_value(self) -> String {
        self.to_string()
    }
}
