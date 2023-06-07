use std::collections::HashSet;

use crate::search::QueryParams;
use crate::server::{fetch_object, SharedState};
use actix_web::web::ServiceConfig;
use actix_web::{web, HttpResponse, Responder};
use serde_json::json;
use spog_model::search::SearchResult;
use trustification_index::IndexStore;
use vexination_model::prelude::*;

const MAX_LIMIT: usize = 1_000;

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(web::resource("/api/v1/advisory/search").to(search));
        config.service(web::resource("/api/v1/advisory").to(get));
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct GetParams {
    pub id: String,
}

pub async fn get(state: web::Data<SharedState>, params: web::Query<GetParams>) -> impl Responder {
    let params = params.into_inner();
    let state = &state.vex;
    let storage = state.storage.read().await;

    // TODO: Stream
    if let Some(obj) = fetch_object(&storage, &params.id).await {
        HttpResponse::Ok().json(obj)
    } else {
        HttpResponse::NotFound().finish()
    }
}

pub async fn search(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> impl Responder {
    let params = params.into_inner();
    tracing::trace!("Querying VEX using {}", params.q);
    let state = &state.vex;

    let index = state.index.read().await;
    let result = search_vex(&index, &params.q, params.offset, params.limit.min(MAX_LIMIT)).await;

    let result = match result {
        Err(e) => {
            tracing::info!("Error searching: {:?}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        Ok(result) => result,
    };

    let mut ret: Vec<serde_json::Value> = Vec::new();
    let storage = state.storage.read().await;

    // Dedup data
    let mut dedup: HashSet<String> = HashSet::new();

    // TODO: stream these
    for key in result.iter() {
        if !dedup.contains(&key.advisory) {
            if let Some(obj) = fetch_object(&storage, &key.advisory).await {
                if let Ok(data) = serde_json::from_slice(&obj[..]) {
                    ret.push(data);
                    dedup.insert(key.advisory.clone());
                }
            }
        }
    }

    HttpResponse::Ok().json(json!({
        "result": ret,
        "total": result.total,
    }))
}

async fn search_vex(
    index: &IndexStore<vexination_index::Index>,
    q: &str,
    offset: usize,
    limit: usize,
) -> anyhow::Result<SearchResult<Vec<SearchDocument>>> {
    Ok(index.search(q, offset, limit)?.into())
}
