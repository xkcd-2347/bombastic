use core::str::FromStr;

use bombastic_model::prelude::*;
use cyclonedx_bom::models::{
    component::Classification,
    hash::HashAlgorithm,
    license::{LicenseChoice, LicenseIdentifier},
};
use search::*;
use sikula::prelude::*;
use spdx_rs::models::Algorithm;
use tantivy::{query::AllQuery, schema::INDEXED, store::ZstdCompressor, IndexSettings, Searcher, SnippetGenerator};
use time::format_description::well_known::Rfc3339;
use tracing::{debug, info, trace, warn};
use trustification_index::{
    create_boolean_query, create_date_query, primary2occur,
    tantivy::{
        doc,
        query::{Occur, Query},
        schema::{Field, Schema, Term, FAST, STORED, STRING, TEXT},
        DateTime,
    },
    term2query, Document, Error as SearchError,
};

mod search;

pub struct Index {
    schema: Schema,
    fields: Fields,
}

pub enum SBOM {
    CycloneDX(cyclonedx_bom::prelude::Bom),
    SPDX(spdx_rs::models::SPDX),
}

impl SBOM {
    pub fn parse(data: &[u8]) -> Result<Self, serde_json::Error> {
        if let Ok(bom) = cyclonedx_bom::prelude::Bom::parse_from_json_v1_3(data) {
            Ok(SBOM::CycloneDX(bom))
        } else {
            let spdx = serde_json::from_slice::<spdx_rs::models::SPDX>(data).map_err(|e| {
                warn!("Error parsing SPDX: {:?}", e);
                e
            })?;
            Ok(SBOM::SPDX(spdx))
        }
    }
}

struct Fields {
    sbom_id: Field,
    dependent: Field,
    created: Field,
    purl: Field,
    name: Field,
    cpe: Field,
    ptype: Field,
    pnamespace: Field,
    pname: Field,
    pversion: Field,
    description: Field,
    sha256: Field,
    license: Field,
    qualifiers: Field,
    supplier: Field,
    classifier: Field,
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Index {
    pub fn new() -> Self {
        let mut schema = Schema::builder();
        let fields = Fields {
            sbom_id: schema.add_text_field("sbom_id", STRING | STORED),
            dependent: schema.add_text_field("dependent", STRING | STORED),
            cpe: schema.add_text_field("cpe", STRING | STORED),
            name: schema.add_text_field("name", STRING | STORED),
            purl: schema.add_text_field("purl", STRING | FAST | STORED),
            ptype: schema.add_text_field("ptype", STRING),
            pnamespace: schema.add_text_field("pnamespace", STRING),
            created: schema.add_date_field("created", INDEXED | FAST | STORED),
            pname: schema.add_text_field("pname", STRING),
            pversion: schema.add_text_field("pversion", STRING | STORED),
            description: schema.add_text_field("description", TEXT | STORED),
            sha256: schema.add_text_field("sha256", STRING | STORED),
            license: schema.add_text_field("license", STRING | STORED),
            supplier: schema.add_text_field("supplier", TEXT | STORED),
            qualifiers: schema.add_text_field("qualifiers", STRING),
            classifier: schema.add_text_field("classifier", STRING | STORED),
        };
        Self {
            schema: schema.build(),
            fields,
        }
    }

    fn index_spdx(&self, id: &str, bom: &spdx_rs::models::SPDX) -> Result<Vec<Document>, SearchError> {
        debug!("Indexing SPDX document");
        let mut documents = Vec::new();
        let mut parents: Vec<String> = Vec::new();

        for package in &bom.package_information {
            if bom
                .document_creation_information
                .document_describes
                .contains(&package.package_spdx_identifier)
            {
                for r in &package.external_reference {
                    parents.push(r.reference_locator.clone());
                }
            }
        }

        for package in &bom.package_information {
            if !bom
                .document_creation_information
                .document_describes
                .contains(&package.package_spdx_identifier)
            {
                for parent in &parents {
                    let mut document = doc!();

                    if let Some(comment) = &package.package_summary_description {
                        document.add_text(self.fields.description, comment);
                    }

                    let created = &bom.document_creation_information.creation_info.created;
                    document.add_date(
                        self.fields.created,
                        DateTime::from_timestamp_millis(created.timestamp_millis()),
                    );

                    for r in package.external_reference.iter() {
                        if r.reference_type == "cpe22type" {
                            document.add_text(self.fields.cpe, &r.reference_locator);
                        }
                        if r.reference_type == "purl" {
                            let purl = r.reference_locator.clone();
                            document.add_text(self.fields.purl, &purl);

                            if let Ok(package) = packageurl::PackageUrl::from_str(&purl) {
                                document.add_text(self.fields.pname, package.name());
                                if let Some(namespace) = package.namespace() {
                                    document.add_text(self.fields.pnamespace, namespace);
                                }

                                if let Some(version) = package.version() {
                                    document.add_text(self.fields.pversion, version);
                                }

                                for entry in package.qualifiers().iter() {
                                    document.add_text(self.fields.qualifiers, entry.1);
                                }
                                document.add_text(self.fields.ptype, package.ty());
                            }
                        }
                    }

                    document.add_text(self.fields.name, &package.package_name);

                    for sum in package.package_checksum.iter() {
                        if sum.algorithm == Algorithm::SHA256 {
                            document.add_text(self.fields.sha256, &sum.value);
                        }
                    }

                    document.add_text(self.fields.license, package.declared_license.to_string());
                    document.add_text(self.fields.dependent, parent);
                    if let Some(supplier) = &package.package_supplier {
                        document.add_text(self.fields.supplier, supplier);
                    }

                    document.add_text(self.fields.sbom_id, id);

                    documents.push(document);
                }
            }
        }
        Ok(documents)
    }

    fn index_cyclonedx(&self, id: &str, bom: &cyclonedx_bom::prelude::Bom) -> Result<Vec<Document>, SearchError> {
        let mut documents = Vec::new();
        let mut parent = None;

        let mut created = None;

        if let Some(metadata) = &bom.metadata {
            if let Some(timestamp) = &metadata.timestamp {
                let timestamp = timestamp.to_string();
                if let Ok(d) = time::OffsetDateTime::parse(&timestamp, &Rfc3339) {
                    created.replace(DateTime::from_timestamp_secs(d.unix_timestamp()));
                }
            }
            if let Some(component) = &metadata.component {
                let mut doc = self.index_cyclonedx_component(id, component, None)?;
                if let Some(created) = &created {
                    doc.add_date(self.fields.created, created.clone());
                }
                documents.push(doc);
                if let Some(purl) = &component.purl {
                    parent.replace(purl.to_string());
                }
            }
        }

        if let Some(components) = &bom.components {
            for component in components.0.iter() {
                let mut doc = self.index_cyclonedx_component(id, component, parent.as_deref())?;
                if let Some(created) = &created {
                    doc.add_date(self.fields.created, created.clone());
                }

                documents.push(doc);
            }
        }
        Ok(documents)
    }

    fn index_cyclonedx_component(
        &self,
        id: &str,
        component: &cyclonedx_bom::prelude::Component,
        parent: Option<&str>,
    ) -> Result<Document, SearchError> {
        let mut document = doc!();

        document.add_text(self.fields.sbom_id, id);
        if let Some(hashes) = &component.hashes {
            for hash in hashes.0.iter() {
                if hash.alg == HashAlgorithm::SHA256 {
                    document.add_text(self.fields.sha256, &hash.content.0);
                }
            }
        }

        if let Some(purl) = &component.purl {
            let purl = purl.to_string();
            document.add_text(self.fields.purl, &purl);

            if let Ok(package) = packageurl::PackageUrl::from_str(&purl) {
                document.add_text(self.fields.pname, package.name());
                document.add_text(self.fields.name, package.name());
                if let Some(namespace) = package.namespace() {
                    document.add_text(self.fields.pnamespace, namespace);
                }

                if let Some(version) = package.version() {
                    document.add_text(self.fields.pversion, version);
                }

                for entry in package.qualifiers().iter() {
                    document.add_text(self.fields.qualifiers, entry.1);
                }
                document.add_text(self.fields.ptype, package.ty());
            }
        }

        if let Some(desc) = &component.description {
            document.add_text(self.fields.description, desc.to_string());
        }

        if let Some(licenses) = &component.licenses {
            licenses.0.iter().for_each(|l| match l {
                LicenseChoice::License(l) => match &l.license_identifier {
                    LicenseIdentifier::Name(s) => {
                        document.add_text(self.fields.license, s.to_string());
                    }
                    LicenseIdentifier::SpdxId(_) => (),
                },
                LicenseChoice::Expression(_) => (),
            });
        }

        document.add_text(self.fields.classifier, component.component_type.to_string());

        if let Some(parent) = parent {
            document.add_text(self.fields.dependent, parent);
        }

        Ok(document)
    }

    fn resource2query(&self, resource: &Packages) -> Box<dyn Query> {
        match resource {
            Packages::Dependent(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.dependent, value);
                create_boolean_query(occur, term)
            }

            Packages::PackageName(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.name, value);
                create_boolean_query(occur, term)
            }

            Packages::Purl(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.purl, value);
                create_boolean_query(occur, term)
            }

            Packages::Type(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.ptype, value);
                create_boolean_query(occur, term)
            }

            Packages::Namespace(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.pnamespace, value);
                create_boolean_query(occur, term)
            }

            Packages::Name(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.pname, value);
                create_boolean_query(occur, term)
            }

            Packages::Version(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.pversion, value);
                create_boolean_query(occur, term)
            }

            Packages::Created(ordered) => create_date_query(self.fields.created, ordered),

            Packages::Description(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.description, value);
                create_boolean_query(occur, term)
            }

            Packages::Digest(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.sha256, value);
                create_boolean_query(occur, term)
            }

            Packages::License(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.license, value);
                create_boolean_query(occur, term)
            }

            Packages::Supplier(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.supplier, value);
                create_boolean_query(occur, term)
            }

            Packages::Qualifier(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.qualifiers, value);
                create_boolean_query(occur, term)
            }

            Packages::Application => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Application.to_string()),
            ),

            Packages::Library => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Library.to_string()),
            ),

            Packages::Framework => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Framework.to_string()),
            ),

            Packages::Container => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Container.to_string()),
            ),

            Packages::OperatingSystem => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::OperatingSystem.to_string()),
            ),

            Packages::Device => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Device.to_string()),
            ),
            Packages::Firmware => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Firmware.to_string()),
            ),
            Packages::File => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::File.to_string()),
            ),
        }
    }
}

impl trustification_index::Index for Index {
    type MatchedDocument = SearchDocument;
    type Document = SBOM;

    fn index_doc(&self, id: &str, doc: &SBOM) -> Result<Vec<Document>, SearchError> {
        match doc {
            SBOM::CycloneDX(bom) => self.index_cyclonedx(id, bom),
            SBOM::SPDX(bom) => self.index_spdx(id, bom),
        }
    }

    fn schema(&self) -> Schema {
        self.schema.clone()
    }

    fn settings(&self) -> IndexSettings {
        IndexSettings {
            sort_by_field: Some(tantivy::IndexSortByField {
                field: self.schema.get_field_name(self.fields.created).to_string(),
                order: tantivy::Order::Desc,
            }),
            docstore_compression: tantivy::store::Compressor::Zstd(ZstdCompressor::default()),
            ..Default::default()
        }
    }

    fn doc_id_to_term(&self, id: &str) -> Term {
        self.schema
            .get_field("sbom_id")
            .map(|f| Term::from_field_text(f, id))
            .unwrap()
    }

    fn prepare_query(&self, q: &str) -> Result<Box<dyn Query>, SearchError> {
        if q.is_empty() {
            return Ok(Box::new(AllQuery));
        }

        let mut query = Packages::parse(q).map_err(|err| SearchError::Parser(err.to_string()))?;

        query.term = query.term.compact();

        info!("Query: {query:?}");

        let query = term2query(&query.term, &|resource| self.resource2query(resource));

        info!("Processed query: {:?}", query);
        Ok(query)
    }

    fn process_hit(
        &self,
        doc: Document,
        searcher: &Searcher,
        query: &dyn Query,
    ) -> Result<Self::MatchedDocument, SearchError> {
        let snippet_generator = SnippetGenerator::create(searcher, query, self.fields.description)?;
        let snippet = snippet_generator.snippet_from_doc(&doc).to_html();

        let id = doc
            .get_first(self.fields.sbom_id)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        if id.is_empty() {
            return Err(SearchError::NotFound);
        }

        let purl = doc
            .get_first(self.fields.purl)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("N/A");

        let name = doc
            .get_first(self.fields.name)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let dependent = doc
            .get_first(self.fields.dependent)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let sha256 = doc
            .get_first(self.fields.sha256)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let license = doc
            .get_first(self.fields.license)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let classifier = doc
            .get_first(self.fields.classifier)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let supplier = doc
            .get_first(self.fields.supplier)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let description = doc
            .get_first(self.fields.description)
            .map(|s| s.as_text().unwrap_or(name))
            .unwrap_or(name);

        let created: time::OffsetDateTime = doc
            .get_first(self.fields.created)
            .map(|s| {
                s.as_date()
                    .map(|d| d.into_utc())
                    .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
            })
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);

        let hit = SearchDocument {
            sbom_id: id.to_string(),
            purl: purl.to_string(),
            name: name.to_string(),
            dependent: dependent.to_string(),
            sha256: sha256.to_string(),
            license: license.to_string(),
            classifier: classifier.to_string(),
            supplier: supplier.to_string(),
            created,
            description: description.to_string(),
            snippet,
        };
        trace!("HIT: {:?}", hit);

        Ok(hit)
    }
}

#[cfg(test)]
mod tests {
    use trustification_index::IndexStore;

    use super::*;

    fn assert_search<F>(f: F)
    where
        F: FnOnce(IndexStore<Index>),
    {
        let _ = env_logger::try_init();

        let index = Index::new();
        let mut store = IndexStore::new_in_memory(index).unwrap();
        let mut writer = store.writer().unwrap();

        let data = std::fs::read_to_string("../testdata/ubi9-sbom.json").unwrap();
        let sbom = SBOM::parse(data.as_bytes()).unwrap();
        writer.add_document(store.index_as_mut(), "ubi9-sbom", &sbom).unwrap();

        let data = std::fs::read_to_string("../testdata/my-sbom.json").unwrap();
        let sbom = SBOM::parse(data.as_bytes()).unwrap();
        writer.add_document(store.index_as_mut(), "my-sbom", &sbom).unwrap();
        writer.commit().unwrap();

        f(store);
    }

    #[tokio::test]
    async fn test_search_form() {
        assert_search(|index| {
            let result = index.search("openssl", 0, 100).unwrap();
            assert_eq!(result.0.len(), 4);
        });
    }

    #[tokio::test]
    async fn test_search_purl() {
        assert_search(|index| {
            let result = index
                .search(
                    "\"pkg:rpm/redhat/openssl-libs@3.0.1-47.el9_1?arch=ppc64le&epoch=1\" in:purl",
                    0,
                    100,
                )
                .unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_search_namespace() {
        assert_search(|index| {
            let result = index.search("redhat in:namespace", 0, 10000).unwrap();
            assert_eq!(result.0.len(), 613);
        });
    }

    #[tokio::test]
    async fn test_search_created() {
        assert_search(|index| {
            let result = index.search("created:>2022-01-01", 0, 10000).unwrap();
            assert_eq!(result.0.len(), 712);
        });
    }

    #[tokio::test]
    async fn test_all() {
        assert_search(|index| {
            let result = index.search("", 0, 10000).unwrap();
            // Should get all documents from test data
            assert_eq!(result.0.len(), 712);
        });
    }
}
