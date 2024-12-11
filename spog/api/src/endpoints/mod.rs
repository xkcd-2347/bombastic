pub mod advisory;
pub mod cve;
pub mod dashboard;
pub mod index;
pub mod package;
pub mod sbom;
pub mod suggestion;
pub mod wellknown;

use crate::openapi;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        index::index,
        wellknown::endpoints::endpoints,
        trustification_version::version::version,

        sbom::get,
        sbom::search,
        sbom::get_vulnerabilities,
        advisory::get,
        advisory::search,

        package::package_search,
        package::package_get,
        package::package_related_products,
        package::get_related,
        package::get_dependencies,
        package::get_dependents,

        cve::cve_get,
        cve::cve_search,
    ),

    components(
        schemas(
            openapi::SearchResultSbom,
            openapi::SearchResultVex,
            openapi::SearchResultCve,

            spog_model::pkg::PackageRefList,
            spog_model::pkg::PackageRef,

            spog_model::package_info::PackageInfo,
            spog_model::package_info::PackageProductDetails,
            spog_model::package_info::ProductRelatedToPackage,
            spog_model::package_info::V11yRef,

            spog_model::search::AdvisorySummary,
            spog_model::search::SbomSummary,

            spog_model::suggestion::Suggestion,
            spog_model::suggestion::Action,

            spog_model::vuln::Remediation,
            spog_model::vuln::SbomReport,
            spog_model::vuln::SbomReportVulnerability,
            spog_model::vuln::SummaryEntry,

            trustification_version::VersionInformation,
            trustification_version::Version,
            trustification_version::Git,
            trustification_version::Build,

            v11y_model::search::SearchHitWithDocument,
            v11y_model::search::SearchDocument,
        )
    ),
    tags(
        (name = "package", description = "Package endpoints"),
        (name = "advisory", description = "Advisory endpoints"),
        (name = "sbom", description = "SBOM endpoints"),
        (name = "vulnerability", description = "Vulnerability endpoints"),
        (name = "well-known", description = ".well-known endpoints"),
        (name = "search", description = "Search endpoint"),
    ),
)]
pub struct ApiDoc;
