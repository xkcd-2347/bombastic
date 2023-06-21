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
use tantivy::{
    query::{AllQuery, BooleanQuery},
    schema::INDEXED,
    store::ZstdCompressor,
    IndexSettings, Searcher, SnippetGenerator,
};
use time::format_description::well_known::Rfc3339;
use tracing::{debug, info, warn};
use trustification_index::{
    create_boolean_query, create_date_query, field2str, field2strvec, primary2occur,
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

pub struct PackageFields {
    name: Field,
    version: Field,
    desc: Field,
    purl: Field,
    cpe: Field,
    license: Field,
    supplier: Field,
    classifier: Field,
    sha256: Field,
    purl_type: Field,
    purl_name: Field,
    purl_namespace: Field,
    purl_version: Field,
    purl_qualifiers: Field,
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
    sbom_created: Field,
    sbom_creators: Field,
    sbom: PackageFields,
    dep: PackageFields,
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
            sbom_created: schema.add_date_field("sbom_created", INDEXED | FAST | STORED),
            sbom_creators: schema.add_text_field("sbom_creators", STRING | STORED),
            sbom: PackageFields {
                name: schema.add_text_field("sbom_name", STRING | STORED),
                version: schema.add_text_field("sbom_version", STRING | STORED),
                purl: schema.add_text_field("sbom_purl", STRING | STORED),
                desc: schema.add_text_field("sbom_desc", TEXT | STORED),
                license: schema.add_text_field("sbom_license", TEXT | STORED),
                cpe: schema.add_text_field("sbom_cpe", STRING | STORED),
                supplier: schema.add_text_field("sbom_supplier", TEXT | STORED),
                classifier: schema.add_text_field("sbom_classifier", STRING),
                sha256: schema.add_text_field("sbom_sha256", STRING | STORED),
                purl_type: schema.add_text_field("sbom_purl_type", STRING),
                purl_name: schema.add_text_field("sbom_purl_name", STRING),
                purl_namespace: schema.add_text_field("sbom_purl_namespace", STRING),
                purl_version: schema.add_text_field("sbom_purl_version", STRING),
                purl_qualifiers: schema.add_text_field("sbom_purl_qualifiers", STRING),
            },
            dep: PackageFields {
                name: schema.add_text_field("dep_name", STRING),
                purl: schema.add_text_field("dep_purl", STRING | STORED),
                version: schema.add_text_field("dep_version", STRING),
                desc: schema.add_text_field("dep_desc", TEXT),
                cpe: schema.add_text_field("dep_cpe", STRING | STORED),
                license: schema.add_text_field("dep_license", TEXT | STORED),
                supplier: schema.add_text_field("dep_supplier", TEXT),
                classifier: schema.add_text_field("dep_classifier", STRING),
                sha256: schema.add_text_field("dep_sha256", STRING),
                purl_type: schema.add_text_field("dep_purl_type", STRING),
                purl_name: schema.add_text_field("dep_purl_name", STRING),
                purl_namespace: schema.add_text_field("dep_purl_namespace", STRING),
                purl_version: schema.add_text_field("dep_purl_version", STRING),
                purl_qualifiers: schema.add_text_field("dep_purl_qualifiers", STRING),
            },
        };
        Self {
            schema: schema.build(),
            fields,
        }
    }

    fn index_spdx(&self, id: &str, bom: &spdx_rs::models::SPDX) -> Result<Vec<Document>, SearchError> {
        debug!("Indexing SPDX document");

        let mut document = doc!();

        document.add_text(self.fields.sbom_id, id);

        for creators in &bom.document_creation_information.creation_info.creators {
            document.add_text(self.fields.sbom_creators, creators);
        }

        let created = &bom.document_creation_information.creation_info.created;
        document.add_date(
            self.fields.sbom_created,
            DateTime::from_timestamp_millis(created.timestamp_millis()),
        );

        for package in &bom.package_information {
            if bom
                .document_creation_information
                .document_describes
                .contains(&package.package_spdx_identifier)
            {
                info!("Indexing SBOM {} with name {}", id, package.package_name);
                Self::index_spdx_package(&mut document, package, &self.fields.sbom);
            } else {
                Self::index_spdx_package(&mut document, package, &self.fields.dep);
            }
        }
        debug!("Indexed {:?}", document);
        Ok(vec![document])
    }

    fn index_spdx_package(
        document: &mut Document,
        package: &spdx_rs::models::PackageInformation,
        fields: &PackageFields,
    ) {
        if let Some(comment) = &package.package_summary_description {
            document.add_text(fields.desc, comment);
        }
        for r in package.external_reference.iter() {
            if r.reference_type == "cpe22type" {
                document.add_text(fields.cpe, &r.reference_locator);
            }
            if r.reference_type == "purl" {
                let purl = r.reference_locator.clone();
                document.add_text(fields.purl, &purl);

                if let Ok(package) = packageurl::PackageUrl::from_str(&purl) {
                    document.add_text(fields.purl_name, package.name());
                    if let Some(namespace) = package.namespace() {
                        document.add_text(fields.purl_namespace, namespace);
                    }

                    if let Some(version) = package.version() {
                        document.add_text(fields.purl_version, version);
                    }

                    for entry in package.qualifiers().iter() {
                        document.add_text(fields.purl_qualifiers, entry.1);
                    }

                    document.add_text(fields.purl_type, package.ty());
                }
            }
        }

        document.add_text(fields.name, &package.package_name);
        if let Some(version) = &package.package_version {
            document.add_text(fields.version, version);
        }

        for sum in package.package_checksum.iter() {
            if sum.algorithm == Algorithm::SHA256 {
                document.add_text(fields.sha256, &sum.value);
            }
        }

        document.add_text(fields.license, package.declared_license.to_string());
        if let Some(supplier) = &package.package_supplier {
            document.add_text(fields.supplier, supplier);
        }
    }

    fn index_cyclonedx(&self, id: &str, bom: &cyclonedx_bom::prelude::Bom) -> Result<Vec<Document>, SearchError> {
        let mut document = doc!();

        document.add_text(self.fields.sbom_id, id);
        if let Some(metadata) = &bom.metadata {
            if let Some(timestamp) = &metadata.timestamp {
                let timestamp = timestamp.to_string();
                if let Ok(d) = time::OffsetDateTime::parse(&timestamp, &Rfc3339) {
                    document.add_date(
                        self.fields.sbom_created,
                        DateTime::from_timestamp_secs(d.unix_timestamp()),
                    );
                }
            }

            if let Some(component) = &metadata.component {
                Self::index_cyclonedx_component(&mut document, component, &self.fields.sbom);
            }
        }

        if let Some(components) = &bom.components {
            for component in components.0.iter() {
                Self::index_cyclonedx_component(&mut document, component, &self.fields.dep);
            }
        }
        Ok(vec![document])
    }

    fn index_cyclonedx_component(
        document: &mut Document,
        component: &cyclonedx_bom::prelude::Component,
        fields: &PackageFields,
    ) {
        if let Some(hashes) = &component.hashes {
            for hash in hashes.0.iter() {
                if hash.alg == HashAlgorithm::SHA256 {
                    document.add_text(fields.sha256, &hash.content.0);
                }
            }
        }

        document.add_text(fields.name, component.name.to_string());
        document.add_text(fields.version, component.version.to_string());

        if let Some(purl) = &component.purl {
            let purl = purl.to_string();
            document.add_text(fields.purl, &purl);

            if let Ok(package) = packageurl::PackageUrl::from_str(&purl) {
                document.add_text(fields.purl_name, package.name());
                if let Some(namespace) = package.namespace() {
                    document.add_text(fields.purl_namespace, namespace);
                }

                if let Some(version) = package.version() {
                    document.add_text(fields.purl_version, version);
                }

                for entry in package.qualifiers().iter() {
                    document.add_text(fields.purl_qualifiers, entry.1);
                }
                document.add_text(fields.purl_type, package.ty());
            }
        }

        if let Some(desc) = &component.description {
            document.add_text(fields.desc, desc.to_string());
        }

        if let Some(licenses) = &component.licenses {
            licenses.0.iter().for_each(|l| match l {
                LicenseChoice::License(l) => match &l.license_identifier {
                    LicenseIdentifier::Name(s) => {
                        document.add_text(fields.license, s.to_string());
                    }
                    LicenseIdentifier::SpdxId(_) => (),
                },
                LicenseChoice::Expression(_) => (),
            });
        }

        document.add_text(fields.classifier, component.component_type.to_string());
    }

    fn resource2query(&self, resource: &Packages) -> Box<dyn Query> {
        match resource {
            Packages::Package(primary) => self.match_boolean_union(
                &[
                    self.fields.sbom.name,
                    self.fields.sbom.purl,
                    self.fields.sbom.cpe,
                    self.fields.sbom.purl_name,
                ],
                primary,
            ),

            Packages::Type(primary) => self.match_boolean_union(&[self.fields.sbom.purl_type], primary),

            Packages::Namespace(primary) => self.match_boolean_union(&[self.fields.sbom.purl_namespace], primary),

            Packages::Created(ordered) => create_date_query(self.fields.sbom_created, ordered),

            Packages::Version(primary) => {
                self.match_boolean_union(&[self.fields.sbom.purl_version, self.fields.sbom.version], primary)
            }

            Packages::Description(primary) => self.match_boolean_union(&[self.fields.sbom.desc], primary),

            Packages::Digest(primary) => self.match_boolean_union(&[self.fields.sbom.sha256], primary),

            Packages::License(primary) => self.match_boolean_union(&[self.fields.sbom.license], primary),

            Packages::Supplier(primary) => self.match_boolean_union(&[self.fields.sbom.supplier], primary),

            Packages::Qualifier(primary) => self.match_boolean_union(&[self.fields.sbom.purl_qualifiers], primary),

            Packages::Dependency(primary) => self.match_boolean_union(
                &[
                    self.fields.dep.name,
                    self.fields.dep.purl_name,
                    self.fields.dep.purl,
                    self.fields.dep.cpe,
                ],
                primary,
            ),

            Packages::Application => self.match_classifiers(Classification::Application),
            Packages::Library => self.match_classifiers(Classification::Library),
            Packages::Framework => self.match_classifiers(Classification::Framework),
            Packages::Container => self.match_classifiers(Classification::Container),
            Packages::OperatingSystem => self.match_classifiers(Classification::OperatingSystem),
            Packages::Device => self.match_classifiers(Classification::Device),
            Packages::Firmware => self.match_classifiers(Classification::Firmware),
            Packages::File => self.match_classifiers(Classification::File),
        }
    }

    fn match_boolean_union(&self, fields: &[Field], value: &Primary<'_>) -> Box<dyn Query> {
        let (occur, value) = primary2occur(value);
        let queries: Vec<Box<dyn Query>> = fields
            .iter()
            .map(|f| create_boolean_query(occur, Term::from_field_text(*f, value)))
            .collect();

        Box::new(BooleanQuery::union(queries))
    }

    fn match_classifiers(&self, classification: Classification) -> Box<dyn Query> {
        Box::new(BooleanQuery::union(vec![
            create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.sbom.classifier, &classification.to_string()),
            ),
            create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.dep.classifier, &classification.to_string()),
            ),
        ]))
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
                field: self.schema.get_field_name(self.fields.sbom_created).to_string(),
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
        let id = field2str(&doc, self.fields.sbom_id)?;

        let snippet_generator = SnippetGenerator::create(searcher, query, self.fields.sbom.desc)?;
        let snippet = snippet_generator.snippet_from_doc(&doc).to_html();

        let purl = doc
            .get_first(self.fields.sbom.purl)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("N/A");

        let cpe = doc
            .get_first(self.fields.sbom.cpe)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("N/A");

        let name = doc
            .get_first(self.fields.sbom.name)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let version = doc
            .get_first(self.fields.sbom.version)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let sha256 = doc
            .get_first(self.fields.sbom.sha256)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let license = doc
            .get_first(self.fields.sbom.license)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let classifier = doc
            .get_first(self.fields.sbom.classifier)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let supplier = doc
            .get_first(self.fields.sbom.supplier)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let description = doc
            .get_first(self.fields.sbom.desc)
            .map(|s| s.as_text().unwrap_or(name))
            .unwrap_or(name);

        let created: time::OffsetDateTime = doc
            .get_first(self.fields.sbom_created)
            .map(|s| {
                s.as_date()
                    .map(|d| d.into_utc())
                    .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
            })
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);

        let dependencies: Vec<String> = field2strvec(&doc, self.fields.dep.purl)?
            .iter()
            .map(|s| s.to_string())
            .collect();

        let hit = SearchDocument {
            id: id.to_string(),
            version: version.to_string(),
            purl: purl.to_string(),
            cpe: cpe.to_string(),
            name: name.to_string(),
            sha256: sha256.to_string(),
            license: license.to_string(),
            classifier: classifier.to_string(),
            supplier: supplier.to_string(),
            snippet,
            created,
            description: description.to_string(),
            dependencies,
        };
        info!("HIT: {:?}", hit);

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
            let result = index.search("ubi9-container", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_search_package() {
        assert_search(|index| {
            let result = index
                .search(
"\"pkg:oci/ubi9@sha256:cb303404e576ff5528d4f08b12ad85fab8f61fa9e5dba67b37b119db24865df3?repository_url=registry.redhat.io/ubi9&tag=9.1.0-1782\" in:package",
                    0,
                    100,
                )
                .unwrap();
            assert_eq!(result.0.len(), 1);

            let result = index.search("ubi9-container in:package", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_search_namespace() {
        assert_search(|index| {
            let result = index.search("namespace:io.seedwing", 0, 10000).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_search_created() {
        assert_search(|index| {
            let result = index.search("created:>2022-01-01", 0, 10000).unwrap();
            assert_eq!(result.0.len(), 2);
        });
    }

    #[tokio::test]
    async fn test_all() {
        assert_search(|index| {
            let result = index.search("", 0, 10000).unwrap();
            // Should get all documents from test data
            assert_eq!(result.0.len(), 2);
        });
    }

    #[tokio::test]
    async fn test_dependency() {
        assert_search(|index| {
            let result = index.search("dependency:openssl", 0, 10000).unwrap();
            // Should get all documents from test data
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_quarkus() {
        assert_search(|index| {
            let result = index.search("dependency:quarkus-arc", 0, 10000).unwrap();
            // Should get all documents from test data
            assert_eq!(result.0.len(), 1);
        });
    }
}
