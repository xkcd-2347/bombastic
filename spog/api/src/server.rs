use std::sync::Arc;

use crate::Run;
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::RwLock;
use trustification_index::IndexStore;
use trustification_storage::Storage;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub struct Server {
    run: Run,
}

#[derive(OpenApi)]
#[openapi(
       // paths(
       //     crate::advisory::search,
       //     crate::sbom::search,
       //     crate::vulnerability::search,
       // ),
        //components(
        //    schemas(package::Package, package::PackageList, package::PackageDependencies, package::PackageDependents, package::PackageRef, package::SnykData, package::VulnerabilityRef, vulnerability::Vulnerability)
        //),
        //tags(
        //    (name = "package", description = "Package query endpoints."),
        //    (name = "vulnerability", description = "Vulnerability query endpoints")
        //),
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
                .configure(crate::vulnerability::configure())
                .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
        })
        .bind((self.run.bind, self.run.port))?
        .run()
        .await?;
        Ok(())
    }
}

pub struct AppState {
    pub sbom: ServiceState<bombastic_index::Index>,
    pub vex: ServiceState<vexination_index::Index>,
}

pub struct ServiceState<T: trustification_index::Index> {
    // TODO: Use APIs for retrieving storage?
    pub storage: RwLock<Storage>,
    pub index: RwLock<IndexStore<T>>,
}

pub type SharedState = Arc<AppState>;

impl<T: trustification_index::Index> ServiceState<T> {
    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let data = {
            let storage = self.storage.read().await;
            storage.get_index().await?
        };

        let mut index = self.index.write().await;
        index.reload(&data[..])?;
        tracing::info!("Index reloaded");
        Ok(())
    }
}

impl AppState {
    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let vex = self.vex.sync_index().await;
        let sbom = self.sbom.sync_index().await;
        if vex.is_err() {
            tracing::info!("Error syncing vexination index: {:?}", vex);
            return vex;
        }
        if sbom.is_err() {
            tracing::info!("Error syncing bombastic index: {:?}", sbom);
            return sbom;
        }
        Ok(())
    }
}

pub(crate) fn configure(run: &Run) -> anyhow::Result<Arc<AppState>> {
    let base_dir: PathBuf = run.index.clone().unwrap_or_else(|| {
        use rand::RngCore;
        let r = rand::thread_rng().next_u32();
        std::env::temp_dir().join(format!("search-api.{}", r))
    });

    let (bombastic_dir, vexination_dir): (PathBuf, PathBuf) = (base_dir.join("bombastic"), base_dir.join("vexination"));

    std::fs::create_dir(&base_dir)?;
    std::fs::create_dir(&bombastic_dir)?;
    std::fs::create_dir(&vexination_dir)?;

    let vexination_index = IndexStore::new(&vexination_dir, vexination_index::Index::new())?;
    let bombastic_index = IndexStore::new(&bombastic_dir, bombastic_index::Index::new())?;

    // TODO: Storage with multiple buckets (bombastic and vexination?)
    // OR: use APIs
    let vexination_storage = trustification_storage::create("vexination", run.devmode, run.storage_endpoint.clone())?;
    let bombastic_storage = trustification_storage::create("bombastic", run.devmode, run.storage_endpoint.clone())?;

    let state = Arc::new(AppState {
        vex: ServiceState {
            storage: RwLock::new(vexination_storage),
            index: RwLock::new(vexination_index),
        },
        sbom: ServiceState {
            storage: RwLock::new(bombastic_storage),
            index: RwLock::new(bombastic_index),
        },
    });

    let sync_interval = Duration::from_secs(run.sync_interval_seconds);

    let sinker = state.clone();
    tokio::task::spawn(async move {
        loop {
            if sinker.sync_index().await.is_ok() {
                tracing::info!("Initial index synced");
                break;
            } else {
                tracing::warn!("Index not yet available");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        loop {
            if let Err(e) = sinker.sync_index().await {
                tracing::info!("Unable to synchronize index: {:?}", e);
            }
            tokio::time::sleep(sync_interval).await;
        }
    });

    Ok(state)
}

pub async fn fetch_object(storage: &Storage, key: &str) -> Option<Vec<u8>> {
    match storage.get(key).await {
        Ok(data) => Some(data),
        Err(e) => {
            tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
            None
        }
    }
}
