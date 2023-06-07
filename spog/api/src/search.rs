use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub q: String,
    #[serde(default = "default_offset")]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

const fn default_offset() -> usize {
    0
}

const fn default_limit() -> usize {
    10
}
