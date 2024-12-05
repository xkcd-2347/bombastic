//! Trustification Index
//!
//! This crate provides a wrapper around the tantivy index for the trustification project.
//!

pub mod metadata;

pub use sort::*;

mod s3dir;
mod sort;

// Re-export to align versions
pub use tantivy;
pub use tantivy::schema::Document;

use bytesize::ByteSize;
use parking_lot::RwLock;
use prometheus::{
    histogram_opts, opts, register_histogram_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry, Histogram, IntCounter, IntGauge, Registry,
};
use s3dir::S3Directory;
use sha2::{Digest, Sha256};
use sikula::{
    lir::PartialOrdered,
    prelude::{Ordered, Primary, Search},
};
use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    ops::Bound,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tantivy::{
    collector::TopDocs,
    directory::{MmapDirectory, INDEX_WRITER_LOCK},
    query::{AllQuery, BooleanQuery, BoostQuery, FuzzyTermQuery, Occur, Query, RangeQuery, RegexQuery, TermQuery},
    schema::*,
    tokenizer::TokenizerManager,
    DateTime, Directory, DocAddress, Index as SearchIndex, IndexSettings, Order, Searcher,
};
use time::{OffsetDateTime, UtcOffset};
use tokio::{spawn, sync::oneshot};
use trustification_api::search::SearchOptions;
use trustification_storage::{Storage, StorageConfig};

/// Configuration for the index.
#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE", next_help_heading = "Index")]
pub struct IndexConfig {
    /// Local folder to store index.
    #[arg(env = "INDEX_DIR", short = 'i', long = "index-dir")]
    pub index_dir: Option<std::path::PathBuf>,

    /// Synchronization interval for index persistence.
    #[arg(env = "INDEX_SYNC_INTERVAL", long = "index-sync-interval", default_value = "30s")]
    pub sync_interval: humantime::Duration,

    /// Memory available to index writerl
    #[arg(env = "INDEX_WRITER_MEMORY_BYTES", long = "index-writer-memory-bytes", default_value_t = ByteSize::mb(256))]
    pub index_writer_memory_bytes: ByteSize,

    /// Synchronization interval for index persistence.
    #[arg(env = "INDEX_MODE", long = "index-mode", default_value_t = IndexMode::File)]
    pub mode: IndexMode,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum IndexMode {
    File,
    S3,
}

impl Display for IndexMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "file"),
            Self::S3 => write!(f, "s3"),
        }
    }
}

impl Default for IndexMode {
    fn default() -> Self {
        Self::File
    }
}

#[derive(Clone)]
struct Metrics {
    indexed_total: IntCounter,
    failed_total: IntCounter,
    snapshots_total: IntCounter,
    queries_total: IntCounter,
    index_size_disk_bytes: IntGauge,
    indexing_latency_seconds: Histogram,
    query_latency_seconds: Histogram,
    documents: IntGauge,
    count_errors: IntCounter,
    count_latency_seconds: Histogram,
}

impl Metrics {
    fn register(registry: &Registry, prefix: &str) -> Result<Self, Error> {
        let prefix = prefix.replace('-', "_");
        let indexed_total = register_int_counter_with_registry!(
            opts!(
                format!("{}_index_indexed_total", prefix),
                "Total number of indexing operations"
            ),
            registry
        )?;

        let failed_total = register_int_counter_with_registry!(
            opts!(
                format!("{}_index_failed_total", prefix),
                "Total number of indexing operations failed"
            ),
            registry
        )?;

        let queries_total = register_int_counter_with_registry!(
            opts!(
                format!("{}_index_queries_total", prefix),
                "Total number of search queries"
            ),
            registry
        )?;

        let snapshots_total = register_int_counter_with_registry!(
            opts!(
                format!("{}_index_snapshots_total", prefix),
                "Total number of snapshots taken"
            ),
            registry
        )?;

        let index_size_disk_bytes = register_int_gauge_with_registry!(
            opts!(
                format!("{}_index_size_disk_bytes", prefix),
                "Amount of bytes consumed by index on disk"
            ),
            registry
        )?;

        let indexing_latency_seconds = register_histogram_with_registry!(
            histogram_opts!(
                format!("{}_index_indexing_latency_seconds", prefix),
                "Indexing latency",
                vec![0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
            ),
            registry
        )?;

        let query_latency_seconds = register_histogram_with_registry!(
            histogram_opts!(
                format!("{}_index_query_latency_seconds", prefix),
                "Search query latency",
                vec![0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
            ),
            registry
        )?;

        let documents = register_int_gauge_with_registry!(
            opts!(
                format!("{}_index_documents", prefix),
                "Amount of documents known by the index"
            ),
            registry
        )?;

        let count_errors = register_int_counter_with_registry!(
            opts!(
                format!("{}_index_count_errors", prefix),
                "Total number of failing to count the index documents"
            ),
            registry
        )?;

        let count_latency_seconds = register_histogram_with_registry!(
            histogram_opts!(
                format!("{}_index_count_latency_seconds", prefix),
                "Count latency",
                vec![0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
            ),
            registry
        )?;

        Ok(Self {
            indexed_total,
            failed_total,
            snapshots_total,
            queries_total,
            index_size_disk_bytes,
            indexing_latency_seconds,
            query_latency_seconds,
            documents,
            count_errors,
            count_latency_seconds,
        })
    }
}

/// A search index. This is a wrapper around the tantivy index that handles loading and storing of the index to object storage (via the local filesystem).
///
/// The index can be live-loaded and stored to/from object storage while serving queries.
pub struct IndexStore<INDEX> {
    inner: Arc<RwLock<SearchIndex>>,
    index_dir: Option<RwLock<IndexDirectory>>,
    index: INDEX,
    index_writer_memory_bytes: usize,
    metrics: Metrics,

    /// the handle running the counter for the metrics. We need to hold on to this handle.
    shutdown_counter: Option<oneshot::Sender<()>>,
}

impl<INDEX> Drop for IndexStore<INDEX> {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown_counter.take() {
            let _ = shutdown.send(());
        }
    }
}

impl<DOC> WriteIndex for Box<dyn WriteIndex<Document = DOC>> {
    type Document = DOC;
    fn name(&self) -> &str {
        self.as_ref().name()
    }

    fn parse_doc(&self, data: &[u8]) -> Result<Self::Document, Error> {
        self.as_ref().parse_doc(data)
    }

    fn settings(&self) -> IndexSettings {
        self.as_ref().settings()
    }

    fn schema(&self) -> Schema {
        self.as_ref().schema()
    }

    fn index_doc(&self, id: &str, document: &Self::Document) -> Result<Vec<(String, Document)>, Error> {
        self.as_ref().index_doc(id, document)
    }

    fn doc_id_to_term(&self, id: &str) -> Term {
        self.as_ref().doc_id_to_term(id)
    }

    fn tokenizers(&self) -> Result<TokenizerManager, Error> {
        self.as_ref().tokenizers()
    }
}

/// Defines the interface for an index that can be written to.
pub trait WriteIndex {
    /// Input document type expected by the index.
    type Document;
    /// Name of the index. Must be unique across trait implementations.
    fn name(&self) -> &str;
    /// Tokenizers used by the index.
    fn tokenizers(&self) -> Result<TokenizerManager, Error> {
        Ok(TokenizerManager::default())
    }
    /// Parse a document from a byte slice.
    fn parse_doc(&self, data: &[u8]) -> Result<Self::Document, Error>;
    /// Index settings required for this index.
    fn settings(&self) -> IndexSettings;
    /// Schema required for this index.
    fn schema(&self) -> Schema;
    /// Process an input document and return a tantivy document to be added to the index.
    fn index_doc(&self, id: &str, document: &Self::Document) -> Result<Vec<(String, Document)>, Error>;
    /// Convert a document id to a term for referencing that document.
    fn doc_id_to_term(&self, id: &str) -> Term;
}

/// Defines the interface for an index that can be searched.
pub trait Index: WriteIndex {
    /// Type of the matched document returned from a search.
    type MatchedDocument: core::fmt::Debug;

    /// Prepare a query for searching and return a query object.
    fn prepare_query(&self, q: &str) -> Result<SearchQuery, Error>;
    /// Search the index for a query and return a list of matched documents.
    fn search(
        &self,
        searcher: &Searcher,
        query: &dyn Query,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<(f32, DocAddress)>, usize), Error>;
    /// Invoked for every matched document to process the document and return a result.
    fn process_hit(
        &self,
        doc: DocAddress,
        score: f32,
        searcher: &Searcher,
        query: &dyn Query,
        options: &SearchOptions,
    ) -> Result<Self::MatchedDocument, Error>;
}

/// Errors returned by the index.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("error opening index {0}")]
    Open(String),
    #[error("error taking snapshot of index")]
    Snapshot,
    #[error("value for field {0} not found")]
    FieldNotFound(String),
    #[error("field {0} cannot be sorted")]
    NotSortable(String),
    #[error("operation cannot be done because index is not persisted")]
    NotPersisted,
    #[error("error parsing document {0}")]
    DocParser(String),
    #[error("error parsing query {0}")]
    QueryParser(String),
    #[error("error from storage {0}")]
    Storage(trustification_storage::Error),
    #[error("invalid limit parameter {0}")]
    InvalidLimitParameter(usize),
    #[error("error from search {0}")]
    Search(tantivy::TantivyError),
    #[error("error configuring metrics {0}")]
    Prometheus(prometheus::Error),
    #[error("I/O error {0}")]
    Io(std::io::Error),
}

impl From<prometheus::Error> for Error {
    fn from(e: prometheus::Error) -> Self {
        Self::Prometheus(e)
    }
}

impl From<tantivy::TantivyError> for Error {
    fn from(e: tantivy::TantivyError) -> Self {
        Self::Search(e)
    }
}

impl From<trustification_storage::Error> for Error {
    fn from(e: trustification_storage::Error) -> Self {
        Self::Storage(e)
    }
}

/// A search query.
#[derive(Debug)]
pub struct SearchQuery {
    /// The tantivy query to execute.
    pub query: Box<dyn Query>,
    /// A custom sort order to apply to the results.
    pub sort_by: Option<(Field, Order)>,
}

/// A writer for an index that allows batching document writes before committing a batch.
///
/// Batching document writes can improve performance by reducing the number of commits to the index.
pub struct IndexWriter {
    writer: tantivy::IndexWriter,
    metrics: Metrics,
}

impl IndexWriter {
    /// Add a document to the batch.
    pub fn add_document<DOC>(
        &mut self,
        index: &dyn WriteIndex<Document = DOC>,
        id: &str,
        data: &[u8],
    ) -> Result<(), Error> {
        self.add_document_with_id(index, data, id, |_| id.to_string())
    }

    /// Add a document with a given identifier to the batch.
    pub fn add_document_with_id<DOC, F>(
        &mut self,
        index: &dyn WriteIndex<Document = DOC>,
        data: &[u8],
        name: &str,
        id: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&DOC) -> String,
    {
        let indexing_latency = self.metrics.indexing_latency_seconds.start_timer();
        match index.parse_doc(data) {
            Ok(doc) => {
                let id = &id(&doc);
                let docs = index.index_doc(id, &doc).map_err(|e| {
                    self.metrics.failed_total.inc();
                    e
                })?;
                for (i, doc) in docs {
                    self.delete_document(index, &i);
                    self.writer.add_document(doc).map_err(|e| {
                        self.metrics.failed_total.inc();
                        e
                    })?;
                }

                self.metrics.indexed_total.inc();
            }
            Err(e) => {
                log::warn!("Error parsing document '{name}': {e:?}");
                self.metrics.failed_total.inc();
            }
        }
        self.metrics.indexed_total.inc();
        indexing_latency.observe_duration();
        Ok(())
    }

    /// Commit the batch and consume the writer. May merge index segments.
    pub fn commit(mut self) -> Result<(), Error> {
        self.writer.commit()?;
        self.writer.wait_merging_threads()?;
        Ok(())
    }

    /// Add a delete operation to the batch.
    pub fn delete_document<DOC>(&self, index: &dyn WriteIndex<Document = DOC>, key: &str) {
        let term = index.doc_id_to_term(key);
        self.writer.delete_term(term);
    }
}

/// Represents state of the index on disk and managing index swaps.
#[derive(Debug)]
struct IndexDirectory {
    path: PathBuf,
    state: IndexState,
    digest: Vec<u8>,
}

impl IndexDirectory {
    /// Attempt to build a new index from the serialized zstd data
    pub fn sync(
        &mut self,
        schema: Schema,
        settings: IndexSettings,
        tokenizers: TokenizerManager,
        data: &[u8],
    ) -> Result<Option<SearchIndex>, Error> {
        let digest = Sha256::digest(data).to_vec();
        if self.digest != digest {
            let next = self.state.next();
            let path = next.directory(&self.path);
            let index = self.unpack(schema, settings, tokenizers, data, &path)?;
            self.state = next;
            self.digest = digest;
            Ok(Some(index))
        } else {
            Ok(None)
        }
    }

    pub fn new(path: &PathBuf) -> Result<IndexDirectory, Error> {
        if path.exists() {
            std::fs::remove_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;
        }
        std::fs::create_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;
        let state = IndexState::A;
        Ok(Self {
            digest: Vec::new(),
            path: path.clone(),
            state,
        })
    }

    pub fn reset(
        &mut self,
        settings: IndexSettings,
        schema: Schema,
        tokenizers: TokenizerManager,
    ) -> Result<SearchIndex, Error> {
        let next = self.state.next();
        let path = next.directory(&self.path);
        if path.exists() {
            std::fs::remove_dir_all(&path).map_err(|e| Error::Open(e.to_string()))?;
        }
        std::fs::create_dir_all(&path).map_err(|e| Error::Open(e.to_string()))?;
        let index = self.build_new(settings, schema, tokenizers, &path)?;
        self.state = next;
        Ok(index)
    }

    fn build_new(
        &self,
        settings: IndexSettings,
        schema: Schema,
        tokenizers: TokenizerManager,
        path: &Path,
    ) -> Result<SearchIndex, Error> {
        std::fs::create_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;
        let dir = MmapDirectory::open(path).map_err(|e| Error::Open(e.to_string()))?;
        let builder = SearchIndex::builder()
            .schema(schema)
            .settings(settings)
            .tokenizers(tokenizers);
        let index = builder.open_or_create(dir).map_err(|e| Error::Open(e.to_string()))?;
        Ok(index)
    }

    pub fn build(
        &self,
        settings: IndexSettings,
        schema: Schema,
        tokenizers: TokenizerManager,
    ) -> Result<SearchIndex, Error> {
        let path = self.state.directory(&self.path);
        self.build_new(settings, schema, tokenizers, &path)
    }

    fn unpack(
        &mut self,
        schema: Schema,
        settings: IndexSettings,
        tokenizers: TokenizerManager,
        data: &[u8],
        path: &Path,
    ) -> Result<SearchIndex, Error> {
        if path.exists() {
            std::fs::remove_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;
        }
        std::fs::create_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;

        let dec = zstd::stream::Decoder::new(data).map_err(Error::Io)?;
        let mut archive = tar::Archive::new(dec);
        archive.unpack(path).map_err(Error::Io)?;
        log::trace!("Unpacked into {:?}", path);

        let dir = MmapDirectory::open(path).map_err(|e| Error::Open(e.to_string()))?;
        let builder = SearchIndex::builder()
            .schema(schema)
            .settings(settings)
            .tokenizers(tokenizers);
        let inner = builder.open_or_create(dir).map_err(|e| Error::Open(e.to_string()))?;
        Ok(inner)
    }

    pub fn pack(&mut self) -> Result<Vec<u8>, Error> {
        let path = self.state.directory(&self.path);
        let mut out = Vec::new();
        let enc = zstd::stream::Encoder::new(&mut out, 3).map_err(Error::Io)?;
        let mut archive = tar::Builder::new(enc.auto_finish());
        log::trace!("Packing from {:?}", path);
        archive.append_dir_all("", path).map_err(Error::Io)?;
        drop(archive);
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum IndexState {
    A,
    B,
}

impl IndexState {
    fn directory(&self, root: &Path) -> PathBuf {
        match self {
            Self::A => root.join("a"),
            Self::B => root.join("b"),
        }
    }

    fn next(&self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

impl<INDEX> IndexStore<INDEX>
where
    INDEX: WriteIndex + 'static,
{
    pub fn new_in_memory(index: INDEX) -> Result<Self, Error> {
        let schema = index.schema();
        let settings = index.settings();
        let tokenizers = index.tokenizers()?;
        let builder = SearchIndex::builder()
            .schema(schema)
            .settings(settings)
            .tokenizers(tokenizers);
        let inner = builder.create_in_ram()?;
        let name = index.name().to_string();
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            index,
            index_writer_memory_bytes: 32 * 1024 * 1024,
            index_dir: None,
            metrics: Metrics::register(&Default::default(), &name)?,
            shutdown_counter: None,
        })
    }

    /// runs an internal loop, counting documents and syncing that to the metrics
    async fn run_index_count(inner: Arc<RwLock<SearchIndex>>, metrics: Metrics, mut shutdown: oneshot::Receiver<()>) {
        fn count(inner: &RwLock<SearchIndex>) -> Option<u64> {
            let count = inner.read().reader().ok()?;
            Some(count.searcher().num_docs())
        }

        log::info!("Starting index counter");

        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                     let count = {
                        let _timer = metrics.count_latency_seconds.start_timer();
                        count(&inner)
                     };

                    log::debug!("Counted {count:?} documents in the index");

                    match count {
                        Some(count) => metrics.documents.set(count.clamp(0, i64::MAX as _) as _),
                        None => metrics.count_errors.inc(),
                    }
                },
                _ = &mut shutdown => {
                    log::info!("Shutting down index counter");
                    break;
                }
            }
        }

        log::info!("Exiting index counter");
    }

    pub fn new(
        storage: &StorageConfig,
        config: &IndexConfig,
        index: INDEX,
        metrics_registry: &Registry,
    ) -> Result<Self, Error> {
        match config.mode {
            IndexMode::File => {
                let path = config
                    .index_dir
                    .clone()
                    .unwrap_or_else(|| {
                        use rand::RngCore;
                        let r = rand::thread_rng().next_u32();
                        std::env::temp_dir().join(format!("index.{}", r))
                    })
                    .join(index.name());

                let schema = index.schema();
                let settings = index.settings();
                let tokenizers = index.tokenizers()?;

                let index_dir = IndexDirectory::new(&path)?;
                let inner = index_dir.build(settings, schema, tokenizers)?;
                let name = index.name().to_string();
                let inner = Arc::new(RwLock::new(inner));
                let metrics = Metrics::register(metrics_registry, &name)?;

                let (shutdown_counter, shutdown) = oneshot::channel();
                spawn({
                    let inner = inner.clone();
                    let metrics = metrics.clone();
                    async move { Self::run_index_count(inner, metrics, shutdown).await }
                });

                Ok(Self {
                    inner,
                    index_writer_memory_bytes: config.index_writer_memory_bytes.as_u64() as usize,
                    index_dir: Some(RwLock::new(index_dir)),
                    index,
                    metrics,
                    shutdown_counter: Some(shutdown_counter),
                })
            }
            IndexMode::S3 => {
                let bucket = storage.clone().try_into()?;
                let schema = index.schema();
                let settings = index.settings();
                let tokenizers = index.tokenizers()?;
                let builder = SearchIndex::builder()
                    .schema(schema)
                    .settings(settings)
                    .tokenizers(tokenizers);
                let dir = S3Directory::new(bucket);
                let inner = builder.open_or_create(dir)?;
                let name = index.name().to_string();
                let inner = Arc::new(RwLock::new(inner));
                let metrics = Metrics::register(metrics_registry, &name)?;

                let (shutdown_counter, shutdown) = oneshot::channel();
                spawn({
                    let inner = inner.clone();
                    let metrics = metrics.clone();
                    async move { Self::run_index_count(inner, metrics, shutdown).await }
                });

                Ok(Self {
                    inner,
                    index_writer_memory_bytes: config.index_writer_memory_bytes.as_u64() as usize,
                    index_dir: None,
                    index,
                    metrics,
                    shutdown_counter: Some(shutdown_counter),
                })
            }
        }
    }

    pub fn index(&self) -> &INDEX {
        &self.index
    }

    pub fn index_as_mut(&mut self) -> &mut INDEX {
        &mut self.index
    }

    /// Sync the index from a snapshot.
    ///
    /// NOTE: Only applicable for file indices.
    pub async fn sync(&self, storage: &Storage) -> Result<(), Error> {
        if let Some(index_dir) = &self.index_dir {
            let data = storage.get_index(self.index.name()).await?;
            let mut index_dir = index_dir.write();
            match index_dir.sync(
                self.index.schema(),
                self.index.settings(),
                self.index.tokenizers()?,
                &data,
            ) {
                Ok(Some(index)) => {
                    *self.inner.write() = index;
                    log::debug!("Index replaced");
                }
                Ok(None) => {
                    // No index change
                    log::debug!("No index change");
                }
                Err(e) => {
                    log::warn!("Error syncing index: {:?}, keeping old", e);
                    return Err(e);
                }
            }
            log::debug!("Index reloaded");
        }
        Ok(())
    }

    // Reset the index to an empty state.
    pub fn reset(&mut self) -> Result<(), Error> {
        log::info!("Resetting index");
        if let Some(index_dir) = &self.index_dir {
            let mut index_dir = index_dir.write();
            let index = index_dir.reset(self.index.settings(), self.index.schema(), self.index.tokenizers()?)?;
            let mut inner = self.inner.write();
            *inner = index;
        }
        Ok(())
    }

    pub fn commit(&self, writer: IndexWriter) -> Result<(), Error> {
        writer.commit()?;
        Ok(())
    }

    /// Take a snapshot of the index and push to object storage.
    ///
    /// NOTE: Only applicable for file indices.
    ///
    ///
    // Disable the lint due to a [bug in clippy](https://github.com/rust-lang/rust-clippy/issues/6446).
    #[allow(clippy::await_holding_lock)]
    pub async fn snapshot(&mut self, writer: IndexWriter, storage: &Storage, force: bool) -> Result<(), Error> {
        if let Some(index_dir) = &self.index_dir {
            writer.commit()?;

            let mut dir = index_dir.write();
            let mut inner = self.inner.write();
            inner.directory_mut().sync_directory().map_err(Error::Io)?;
            let lock = inner.directory_mut().acquire_lock(&INDEX_WRITER_LOCK);

            let managed_files = inner.directory().list_managed_files();

            let mut total_size: i64 = 0;
            for file in managed_files.iter() {
                log::trace!("Managed file: {:?}", file);
                let sz = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
                total_size += sz as i64;
            }
            self.metrics.index_size_disk_bytes.set(total_size);
            self.metrics.snapshots_total.inc();

            let gc_result = inner.directory_mut().garbage_collect(|| managed_files)?;
            log::trace!(
                "Gc result. Deleted: {:?}, failed: {:?}",
                gc_result.deleted_files,
                gc_result.failed_to_delete_files
            );
            let changed = !gc_result.deleted_files.is_empty();
            inner.directory_mut().sync_directory().map_err(Error::Io)?;
            if force || changed {
                log::info!("Index has changed, publishing new snapshot");
                let out = dir.pack()?;
                drop(lock);
                drop(inner);
                drop(dir);
                match storage.put_index(self.index.name(), &out).await {
                    Ok(_) => {
                        log::trace!("Snapshot published successfully");
                        Ok(())
                    }
                    Err(e) => {
                        log::warn!("Error updating index: {:?}", e);
                        Err(e.into())
                    }
                }
            } else {
                log::trace!("No changes to index");
                Ok(())
            }
        } else {
            log::trace!("Committing index");
            writer.commit()?;
            Ok(())
        }
    }

    pub fn writer(&mut self) -> Result<IndexWriter, Error> {
        let writer = self.inner.write().writer(self.index_writer_memory_bytes)?;
        Ok(IndexWriter {
            writer,
            metrics: self.metrics.clone(),
        })
    }
}

impl<INDEX: Index> IndexStore<INDEX> {
    /// To obtain the total number of docs.
    pub fn get_total_docs(&self) -> Result<u64, Error> {
        let inner = self.inner.read();
        let reader = inner.reader()?;
        let searcher = reader.searcher();
        Ok(searcher.num_docs())
    }

    /// Search the index for a given query and return matching documents.
    pub fn search(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
    ) -> Result<(Vec<INDEX::MatchedDocument>, usize), Error> {
        let latency = self.metrics.query_latency_seconds.start_timer();

        if limit == 0 {
            return Err(Error::InvalidLimitParameter(limit));
        }

        let inner = self.inner.read();
        let reader = inner.reader()?;
        let searcher = reader.searcher();

        let query = self.index.prepare_query(q)?;

        log::trace!("Processed query: {:?}", query);

        let (top_docs, count) = if let Some(sort_by) = query.sort_by {
            let field = sort_by.0;
            let order = sort_by.1;
            let order_by_str = self.index.schema().get_field_name(field).to_string();
            let vtype = self.index.schema().get_field_entry(field).field_type().value_type();
            let mut hits = Vec::new();
            let total = match vtype {
                Type::U64 => {
                    let result = searcher.search(
                        &query.query,
                        &(
                            TopDocs::with_limit(limit)
                                .and_offset(offset)
                                .order_by_fast_field::<u64>(&order_by_str, order),
                            tantivy::collector::Count,
                        ),
                    )?;
                    for r in result.0 {
                        hits.push((1.0, r.1));
                    }
                    result.1
                }
                Type::I64 => {
                    let result = searcher.search(
                        &query.query,
                        &(
                            TopDocs::with_limit(limit)
                                .and_offset(offset)
                                .order_by_fast_field::<i64>(&order_by_str, order),
                            tantivy::collector::Count,
                        ),
                    )?;
                    for r in result.0 {
                        hits.push((1.0, r.1));
                    }
                    result.1
                }
                Type::F64 => {
                    let result = searcher.search(
                        &query.query,
                        &(
                            TopDocs::with_limit(limit)
                                .and_offset(offset)
                                .order_by_fast_field::<f64>(&order_by_str, order),
                            tantivy::collector::Count,
                        ),
                    )?;
                    for r in result.0 {
                        hits.push((1.0, r.1));
                    }
                    result.1
                }
                Type::Bool => {
                    let result = searcher.search(
                        &query.query,
                        &(
                            TopDocs::with_limit(limit)
                                .and_offset(offset)
                                .order_by_fast_field::<bool>(&order_by_str, order),
                            tantivy::collector::Count,
                        ),
                    )?;
                    for r in result.0 {
                        hits.push((1.0, r.1));
                    }
                    result.1
                }
                Type::Date => {
                    let result = searcher.search(
                        &query.query,
                        &(
                            TopDocs::with_limit(limit)
                                .and_offset(offset)
                                .order_by_fast_field::<DateTime>(&order_by_str, order),
                            tantivy::collector::Count,
                        ),
                    )?;
                    for r in result.0 {
                        hits.push((1.0, r.1));
                    }
                    result.1
                }
                _ => return Err(Error::NotSortable(order_by_str)),
            };
            (hits, total)
        } else {
            self.index.search(&searcher, &query.query, offset, limit)?
        };

        self.metrics.queries_total.inc();

        log::info!("#matches={count} for query '{q}'");

        if options.summaries {
            let mut hits = Vec::new();
            for hit in top_docs {
                match self.index.process_hit(hit.1, hit.0, &searcher, &query.query, &options) {
                    Ok(value) => {
                        log::debug!("HIT: {:?}", value);
                        hits.push(value);
                    }
                    Err(e) => {
                        log::warn!("Error processing hit {:?}: {:?}", hit, e);
                    }
                }
            }

            log::debug!("Filtered to {}", hits.len());

            latency.observe_duration();
            Ok((hits, count))
        } else {
            latency.observe_duration();
            Ok((Vec::new(), count))
        }
    }
}

/// Convert a sikula term to a query
pub fn term2query<'m, R: Search, F: Fn(&R::Parsed<'m>) -> Box<dyn Query>>(
    term: &sikula::prelude::Term<'m, R>,
    f: &F,
) -> Box<dyn Query> {
    match term {
        sikula::prelude::Term::Match(resource) => f(resource),
        sikula::prelude::Term::Not(term) => {
            let all: Box<dyn Query> = Box::new(AllQuery);
            let query_terms = vec![(Occur::Should, all), (Occur::MustNot, term2query(term, f))];
            let query = BooleanQuery::new(query_terms);
            Box::new(query)
        }
        sikula::prelude::Term::And(terms) => {
            let mut query_terms = Vec::new();
            for term in terms {
                query_terms.push(term2query(term, f));
            }
            Box::new(BooleanQuery::intersection(query_terms))
        }
        sikula::prelude::Term::Or(terms) => {
            let mut query_terms = Vec::new();
            for term in terms {
                query_terms.push(term2query(term, f));
            }
            Box::new(BooleanQuery::union(query_terms))
        }
    }
}

/// Crate a i64 query based on an ordered value
pub fn create_i64_query(schema: &Schema, field: Field, value: &Ordered<i64>) -> Box<dyn Query> {
    let field_name = schema.get_field_name(field).to_string();

    match value {
        Ordered::Less(e) => Box::new(RangeQuery::new_term_bounds(
            field_name,
            Type::I64,
            &Bound::Unbounded,
            &Bound::Excluded(Term::from_field_i64(field, *e)),
        )),
        Ordered::LessEqual(e) => Box::new(RangeQuery::new_term_bounds(
            field_name,
            Type::I64,
            &Bound::Unbounded,
            &Bound::Included(Term::from_field_i64(field, *e)),
        )),
        Ordered::Greater(e) => Box::new(RangeQuery::new_term_bounds(
            field_name,
            Type::I64,
            &Bound::Excluded(Term::from_field_i64(field, *e)),
            &Bound::Unbounded,
        )),
        Ordered::GreaterEqual(e) => Box::new(RangeQuery::new_term_bounds(
            field_name,
            Type::I64,
            &Bound::Included(Term::from_field_i64(field, *e)),
            &Bound::Unbounded,
        )),
        Ordered::Equal(e) => {
            let from = Bound::Included(Term::from_field_i64(field, *e));
            let to = Bound::Included(Term::from_field_i64(field, *e));
            Box::new(RangeQuery::new_term_bounds(field_name, Type::I64, &from, &to))
        }
        Ordered::Range(from, to) => {
            let from = bound_map(*from, |f| Term::from_field_i64(field, f));
            let to = bound_map(*to, |f| Term::from_field_i64(field, f));
            Box::new(RangeQuery::new_term_bounds(field_name, Type::I64, &from, &to))
        }
    }
}

/// Crate a date query based on an ordered value
pub fn create_date_query(schema: &Schema, field: Field, value: &Ordered<time::OffsetDateTime>) -> Box<dyn Query> {
    let field_name = schema.get_field_name(field).to_string();

    match value {
        Ordered::Less(e) => Box::new(RangeQuery::new_term_bounds(
            field_name,
            Type::Date,
            &Bound::Unbounded,
            &Bound::Excluded(Term::from_field_date(field, DateTime::from_utc(*e))),
        )),
        Ordered::LessEqual(e) => Box::new(RangeQuery::new_term_bounds(
            field_name,
            Type::Date,
            &Bound::Unbounded,
            &Bound::Included(Term::from_field_date(field, DateTime::from_utc(*e))),
        )),
        Ordered::Greater(e) => Box::new(RangeQuery::new_term_bounds(
            field_name,
            Type::Date,
            &Bound::Excluded(Term::from_field_date(field, DateTime::from_utc(*e))),
            &Bound::Unbounded,
        )),
        Ordered::GreaterEqual(e) => Box::new(RangeQuery::new_term_bounds(
            field_name,
            Type::Date,
            &Bound::Included(Term::from_field_date(field, DateTime::from_utc(*e))),
            &Bound::Unbounded,
        )),
        Ordered::Equal(e) => {
            let theday = e.to_offset(UtcOffset::UTC).date();
            let theday_after = theday.next_day().unwrap_or(theday);

            let theday = theday.midnight().assume_utc();
            let theday_after = theday_after.midnight().assume_utc();

            let from = Bound::Included(Term::from_field_date(field, DateTime::from_utc(theday)));
            let to = Bound::Included(Term::from_field_date(field, DateTime::from_utc(theday_after)));
            Box::new(RangeQuery::new_term_bounds(field_name, Type::Date, &from, &to))
        }
        Ordered::Range(from, to) => {
            let from = bound_map(*from, |f| Term::from_field_date(field, DateTime::from_utc(f)));
            let to = bound_map(*to, |f| Term::from_field_date(field, DateTime::from_utc(f)));
            Box::new(RangeQuery::new_term_bounds(field_name, Type::Date, &from, &to))
        }
    }
}

/// Convert a sikula primary to a tantivy query for string fields
pub fn create_string_query(field: Field, primary: &Primary<'_>) -> Box<dyn Query> {
    create_string_query_case(field, primary, Case::Sensitive)
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum Case {
    #[default]
    Sensitive,
    Lowercase,
    Uppercase,
}

impl Case {
    pub fn to_value<'a>(&self, value: &'a str) -> Cow<'a, str> {
        match self {
            Self::Sensitive => value.into(),
            Self::Lowercase => value.to_lowercase().into(),
            Self::Uppercase => value.to_uppercase().into(),
        }
    }
}

/// Convert a sikula primary to a tantivy query for string fields
pub fn create_string_query_case(field: Field, primary: &Primary<'_>, case: Case) -> Box<dyn Query> {
    match primary {
        Primary::Equal(value) => Box::new(TermQuery::new(
            Term::from_field_text(field, case.to_value(value).as_ref()),
            Default::default(),
        )),
        Primary::Partial(value) => {
            // Note: This could be expensive so consider alternatives
            let pattern = format!(".*{}.*", case.to_value(value));
            let mut queries: Vec<Box<dyn Query>> = Vec::new();
            if let Ok(query) = RegexQuery::from_pattern(&pattern, field) {
                queries.push(Box::new(query));
            } else {
                log::warn!("Unable to partial query from {}", pattern);
            }
            queries.push(Box::new(TermQuery::new(
                Term::from_field_text(field, case.to_value(value).as_ref()),
                Default::default(),
            )));
            Box::new(BooleanQuery::union(queries))
        }
    }
}

/// Convert a sikula primary to a tantivy query for text fields
pub fn create_text_query(field: Field, primary: &Primary<'_>) -> Box<dyn Query> {
    match primary {
        Primary::Equal(value) => Box::new(TermQuery::new(
            Term::from_field_text(field, &value.to_lowercase()),
            Default::default(),
        )),
        Primary::Partial(value) => Box::new(FuzzyTermQuery::new(
            Term::from_field_text(field, &value.to_lowercase()),
            2,
            true,
        )),
    }
}

/// Boost score of a term
pub fn boost(q: Box<dyn Query>, weight: f32) -> Box<dyn Query> {
    Box::new(BoostQuery::new(q, weight))
}

/// Map over a bound
pub fn bound_map<F: FnOnce(T) -> R, T, R>(bound: Bound<T>, func: F) -> Bound<R> {
    match bound {
        Bound::Included(f) => Bound::Included(func(f)),
        Bound::Excluded(f) => Bound::Excluded(func(f)),
        Bound::Unbounded => Bound::Unbounded,
    }
}

/// Create a boolean query
pub fn create_boolean_query(occur: Occur, term: Term) -> Box<dyn Query> {
    Box::new(BooleanQuery::new(vec![(
        occur,
        Box::new(TermQuery::new(term, IndexRecordOption::Basic)),
    )]))
}

/// Create a float query
///
/// Multiple fields will be combined with "or".
pub fn create_float_query<F>(schema: &Schema, fields: F, value: &PartialOrdered<f64>) -> Box<dyn Query>
where
    F: IntoIterator<Item = Field>,
{
    let mut fields = fields
        .into_iter()
        .map(|f| schema.get_field_name(f).to_string())
        .collect::<Vec<_>>();

    let query_field = |field, lower, upper| Box::new(RangeQuery::new_f64_bounds(field, lower, upper)) as Box<dyn Query>;

    let query = move |lower, upper| {
        if fields.len() == 1 {
            query_field(fields.pop().expect("just checked it was one"), lower, upper)
        } else {
            let mut query_terms = Vec::new();
            for field in fields {
                query_terms.push(query_field(field, lower, upper));
            }
            Box::new(BooleanQuery::union(query_terms))
        }
    };

    match value {
        PartialOrdered::Less(e) => query(Bound::Unbounded, Bound::Excluded(*e)),
        PartialOrdered::LessEqual(e) => query(Bound::Unbounded, Bound::Included(*e)),
        PartialOrdered::Greater(e) => query(Bound::Excluded(*e), Bound::Unbounded),
        PartialOrdered::GreaterEqual(e) => query(Bound::Included(*e), Bound::Unbounded),
        PartialOrdered::Range(from, to) => query(*from, *to),
    }
}

pub fn field2strvec(doc: &Document, field: Field) -> Result<Vec<&str>, Error> {
    Ok(doc.get_all(field).map(|s| s.as_text().unwrap_or_default()).collect())
}

pub fn field2f64vec(doc: &Document, field: Field) -> Result<Vec<f64>, Error> {
    Ok(doc.get_all(field).map(|s| s.as_f64().unwrap_or_default()).collect())
}

pub fn field2str<'m>(schema: &'m Schema, doc: &'m Document, field: Field) -> Result<&'m str, Error> {
    let value = doc.get_first(field).map(|s| s.as_text()).unwrap_or(None);
    value
        .map(Ok)
        .unwrap_or_else(|| Err(Error::FieldNotFound(schema.get_field_name(field).to_string())))
}

pub fn field2str_opt(doc: &Document, field: Field) -> Option<&str> {
    doc.get_first(field).map(|s| s.as_text()).unwrap_or(None)
}

pub fn field2bool<'m>(schema: &'m Schema, doc: &'m Document, field: Field) -> Result<bool, Error> {
    let value = doc.get_first(field).map(|s| s.as_bool()).unwrap_or(None);
    value
        .map(Ok)
        .unwrap_or_else(|| Err(Error::FieldNotFound(schema.get_field_name(field).to_string())))
}

/// Get field as mandatory date
pub fn field2date(schema: &Schema, doc: &Document, field: Field) -> Result<OffsetDateTime, Error> {
    field2date_opt(doc, field).ok_or_else(|| Error::FieldNotFound(schema.get_field_name(field).to_string()))
}

/// Get field as optional date
pub fn field2date_opt(doc: &Document, field: Field) -> Option<OffsetDateTime> {
    doc.get_first(field).and_then(|s| s.as_date()).map(|d| d.into_utc())
}

pub fn field2float(schema: &Schema, doc: &Document, field: Field) -> Result<f64, Error> {
    let value = doc.get_first(field).map(|s| s.as_f64()).unwrap_or(None);
    value
        .map(Ok)
        .unwrap_or_else(|| Err(Error::FieldNotFound(schema.get_field_name(field).to_string())))
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use tantivy::collector::TopDocs;
    use tantivy::doc;

    use super::*;

    struct TestIndex {
        schema: Schema,
        id: Field,
        text: Field,
    }

    impl TestIndex {
        pub fn new() -> Self {
            let mut builder = Schema::builder();
            let id = builder.add_text_field("id", STRING | FAST | STORED);
            let text = builder.add_text_field("text", TEXT);
            let schema = builder.build();
            Self { schema, id, text }
        }
    }

    impl Index for TestIndex {
        type MatchedDocument = String;

        fn prepare_query(&self, q: &str) -> Result<SearchQuery, Error> {
            let queries: Vec<Box<dyn Query>> = vec![
                Box::new(TermQuery::new(
                    Term::from_field_text(self.id, q),
                    IndexRecordOption::Basic,
                )),
                Box::new(TermQuery::new(
                    Term::from_field_text(self.text, q),
                    IndexRecordOption::Basic,
                )),
            ];
            Ok(SearchQuery {
                query: Box::new(BooleanQuery::union(queries)),
                sort_by: None,
            })
        }

        fn process_hit(
            &self,
            doc: DocAddress,
            _score: f32,
            searcher: &Searcher,
            _query: &dyn Query,
            _options: &SearchOptions,
        ) -> Result<Self::MatchedDocument, Error> {
            let d = searcher.doc(doc)?;
            let id = d
                .get_first(self.id)
                .map(|v| v.as_text())
                .ok_or(Error::FieldNotFound("id".to_string()))?;
            Ok(id.unwrap_or("").to_string())
        }

        fn search(
            &self,
            searcher: &Searcher,
            query: &dyn Query,
            offset: usize,
            limit: usize,
        ) -> Result<(Vec<(f32, DocAddress)>, usize), Error> {
            Ok(searcher.search(
                query,
                &(TopDocs::with_limit(limit).and_offset(offset), tantivy::collector::Count),
            )?)
        }
    }

    impl WriteIndex for TestIndex {
        type Document = String;

        fn name(&self) -> &str {
            "test"
        }

        fn settings(&self) -> IndexSettings {
            IndexSettings::default()
        }

        fn schema(&self) -> Schema {
            self.schema.clone()
        }

        fn parse_doc(&self, data: &[u8]) -> Result<Self::Document, Error> {
            core::str::from_utf8(data)
                .map_err(|e| Error::DocParser(e.to_string()))
                .map(|s| s.to_string())
        }

        fn index_doc(&self, id: &str, document: &Self::Document) -> Result<Vec<(String, Document)>, Error> {
            let mut documents: Vec<(String, Document)> = Vec::new();
            let doc = tantivy::doc!(
                self.id => id.to_string(),
                self.text => document.to_string()
            );
            documents.push((id.to_string(), doc));
            Ok(documents)
        }

        fn doc_id_to_term(&self, id: &str) -> Term {
            Term::from_field_text(self.id, id)
        }
    }

    #[tokio::test]
    async fn test_basic_index() {
        let _ = env_logger::try_init();
        let mut store = IndexStore::new_in_memory(TestIndex::new()).unwrap();
        let mut writer = store.writer().unwrap();

        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default()).unwrap().1, 1);
    }

    #[tokio::test]
    async fn test_index_removal() {
        let _ = env_logger::try_init();
        let mut store = IndexStore::new_in_memory(TestIndex::new()).unwrap();
        let mut writer = store.writer().unwrap();

        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default()).unwrap().1, 1);

        let writer = store.writer().unwrap();
        writer.delete_document(store.index_as_mut(), "foo");
        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default()).unwrap().1, 0);
    }

    #[tokio::test]
    async fn test_zero_limit() {
        let _ = env_logger::try_init();
        let store = IndexStore::new_in_memory(TestIndex::new()).unwrap();
        assert!(matches!(
            store.search("is", 0, 0, SearchOptions::default()),
            Err(Error::InvalidLimitParameter(0))
        ));
    }

    #[tokio::test]
    async fn test_duplicates() {
        let _ = env_logger::try_init();
        let mut store = IndexStore::new_in_memory(TestIndex::new()).unwrap();
        let mut writer = store.writer().unwrap();

        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default()).unwrap().1, 1);

        // Duplicates also removed if separate commits.
        let mut writer = store.writer().unwrap();
        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default()).unwrap().1, 1);
    }

    #[tokio::test]
    async fn test_directory_sync_failure() {
        let _ = env_logger::try_init();

        let mut old_schema = Schema::builder();
        let old_id = old_schema.add_text_field("id", STRING | FAST | STORED);
        let old_schema = old_schema.build();

        let mut new_schema = Schema::builder();
        new_schema.add_u64_field("id", INDEXED);
        let new_schema = new_schema.build();

        let r = rand::thread_rng().next_u32();
        let dir = std::env::temp_dir().join(format!("index.{}", r));

        let mut good = IndexDirectory::new(&dir.join("good")).unwrap();
        let mut bad = IndexDirectory::new(&dir.join("bad")).unwrap();

        let store = good.build(Default::default(), old_schema, Default::default()).unwrap();

        let mut w = store.writer(15_000_000).unwrap();
        w.add_document(doc!(old_id => "foo")).unwrap();
        w.commit().unwrap();
        w.wait_merging_threads().unwrap();

        let snapshot = good.pack().unwrap();
        let store = bad.build(Default::default(), new_schema, Default::default()).unwrap();
        let schema = store.schema();
        let settings = store.settings();
        let tokenizers = store.tokenizers();

        assert_eq!(bad.state, IndexState::A);
        let result = bad.sync(schema, settings.clone(), tokenizers.clone(), &snapshot);
        assert!(result.is_err());
        assert_eq!(bad.state, IndexState::A);
    }

    #[tokio::test]
    async fn test_index_dir_reset() {
        let _ = env_logger::try_init();

        let mut schema = Schema::builder();
        let id = schema.add_text_field("id", STRING | FAST | STORED);
        let schema = schema.build();

        let r = rand::thread_rng().next_u32();
        let dir = std::env::temp_dir().join(format!("index.{}", r));

        let mut good = IndexDirectory::new(&dir.join("good")).unwrap();

        let store = good
            .build(Default::default(), schema, TokenizerManager::default())
            .unwrap();
        let schema = store.schema();
        let settings = store.settings();
        let tokenizers = store.tokenizers();

        let mut w = store.writer(15_000_000).unwrap();
        w.add_document(doc!(id => "foo")).unwrap();
        w.commit().unwrap();
        w.wait_merging_threads().unwrap();
        assert_eq!(store.reader().unwrap().searcher().num_docs(), 1);

        assert_eq!(good.state, IndexState::A);
        let clean = good.reset(settings.clone(), schema, tokenizers.clone()).unwrap();
        assert_eq!(good.state, IndexState::B);
        assert_eq!(store.reader().unwrap().searcher().num_docs(), 1);
        assert_eq!(clean.reader().unwrap().searcher().num_docs(), 0);
    }
}
