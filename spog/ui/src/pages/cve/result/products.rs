use futures::future::try_join_all;
use patternfly_yew::prelude::*;
use spog_model::{
    prelude::{CveDetails, PackageRelatedToProductCve, ProductCveStatus},
    search::PackageSummary,
};
use spog_ui_backend::{use_backend, PackageService};
use spog_ui_common::utils::time::date;
use spog_ui_components::async_state_renderer::async_content;
use spog_ui_navigation::{AppRoute, View};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::use_async_with_cloned_deps;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

use crate::pages::{cve::result::packages::PackagesTable, search::PaginationWrapped};

#[derive(PartialEq)]
pub struct TableData {
    sbom_id: String,
    status: ProductCveStatus,
    packages: Vec<PackageRelatedToProductCve>,
    sbom: Option<PackageSummary>,
}

trait StatusLabel {
    fn label(&self) -> &'static str;
    fn color(&self) -> Color;
}

impl StatusLabel for ProductCveStatus {
    fn label(&self) -> &'static str {
        match self {
            Self::Fixed => "Fixed",
            Self::FirstFixed => "First fixed",
            Self::FirstAffected => "First Affected",
            Self::KnownAffected => "Known affected",
            Self::LastAffected => "Last affected",
            Self::KnownNotAffected => "Knwon not affected",
            Self::Recommended => "Recommended",
            Self::UnderInvestigation => "Under investigation",
        }
    }

    fn color(&self) -> Color {
        match self {
            Self::Fixed => Color::Green,
            Self::FirstFixed => Color::Green,
            Self::FirstAffected => Color::Red,
            Self::KnownAffected => Color::Red,
            Self::LastAffected => Color::Red,
            Self::KnownNotAffected => Color::Blue,
            Self::Recommended => Color::Orange,
            Self::UnderInvestigation => Color::Grey,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Name,
    Version,
    Status,
    Dependencies,
    Supplier,
    Created,
}

impl TableEntryRenderer<Column> for TableData {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!(
                <Link<AppRoute>
                    target={AppRoute::Sbom(View::Content{id: self.sbom_id.clone()})}
                >
                    { self.sbom_id.clone() }
                </Link<AppRoute>>
            ),
            Column::Version => html!(
                <>
                    {
                        match &self.sbom {
                            Some(val) => html!(
                                <>
                                    {&val.version}
                                </>
                            ),
                            None => html!(<></>),
                        }
                    }
                </>
            ),
            Column::Status => html!(
                <>
                    <Label label={self.status.label().to_string()} color={self.status.color()}/>
                </>
            ),
            Column::Dependencies => html!(
                <>
                    {&self.packages.len()}
                </>
            ),
            Column::Supplier => html!(
                <>
                    {
                        match &self.sbom {
                            Some(val) => html!(
                                <>
                                    {&val.supplier}
                                </>
                            ),
                            None => html!(<></>),
                        }
                    }
                </>
            ),
            Column::Created => html!(
                <>
                    {
                        match &self.sbom {
                            Some(val) => date(val.created).into(),
                            None => html!(<></>),
                        }
                    }
                </>
            ),
        }
        .into()
    }

    fn render_column_details(&self, #[allow(unused)] column: &Column) -> Vec<Span> {
        vec![Span::max(match column {
            Column::Name => html!({ "Name" }),
            Column::Version => html!({ "Version" }),
            Column::Status => html!({ "Status" }),
            Column::Dependencies => html!(<PackagesTable packages={self.packages.clone()} />),
            Column::Supplier => html!({ "Supplier" }),
            Column::Created => html!({ "Created" }),
        })]
    }
}

#[derive(PartialEq, Properties)]
pub struct RelatedProductsProperties {
    pub cve_details: Rc<CveDetails>,
}

#[function_component(RelatedProducts)]
pub fn related_products(props: &RelatedProductsProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let table_data = use_memo(props.cve_details.products.clone(), |map| {
        map.iter()
            .flat_map(|(map_key, map_value)| {
                map_value
                    .iter()
                    .map(|item| TableData {
                        status: map_key.clone(),
                        sbom_id: item.sbom_id.to_string(),
                        packages: item.packages.clone(),
                        sbom: None,
                    })
                    .collect::<Vec<TableData>>()
            })
            .collect::<Vec<_>>()
    });

    let sboms = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |rows| async move {
                let service = PackageService::new(backend.clone(), access_token.clone());
                let futures = rows.iter().map(|row| service.get_package(&row.sbom_id));
                try_join_all(futures)
                    .await
                    .map(|vec| {
                        vec.iter()
                            .map(|search_result| {
                                if search_result.result.len() == 1 {
                                    let sbom = &search_result.result[0];
                                    Some(sbom.clone())
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .map(Rc::new)
                    .map_err(|err| err.to_string())
            },
            table_data.clone(),
        )
    };

    match props.cve_details.products.is_empty() {
        true => html!(
            <Panel>
                <PanelMain>
                    <Bullseye>
                        <EmptyState
                            title="No related products"
                            icon={Icon::Search}
                        >
                            { "No related products have been found." }
                        </EmptyState>
                    </Bullseye>
                </PanelMain>
            </Panel>
        ),
        false => html!(
            <>
                { async_content(&*sboms, |sboms| html!(<RelatedProductsTable {sboms} {table_data} />)) }
            </>
        ),
    }
}

///

#[derive(PartialEq, Properties)]
pub struct RelatedProductsTableProperties {
    pub table_data: Rc<Vec<TableData>>,
    pub sboms: Rc<Vec<Option<PackageSummary>>>,
}

#[function_component(RelatedProductsTable)]
pub fn related_products_table(props: &RelatedProductsTableProperties) -> Html {
    let table_data = use_memo(
        (props.table_data.clone(), props.sboms.clone()),
        |(table_data, sboms)| {
            table_data
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let sbom_by_index = &sboms[index];

                    TableData {
                        status: item.status.clone(),
                        sbom_id: item.sbom_id.clone(),
                        packages: item.packages.clone(),
                        sbom: sbom_by_index.clone(),
                    }
                })
                .collect::<Vec<_>>()
        },
    );

    let total = table_data.len();
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(table_data));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Name" index={Column::Name} />
            <TableColumn<Column> label="Version" index={Column::Version} />
            <TableColumn<Column> label="Status" index={Column::Status} />
            <TableColumn<Column> label="Dependencies" index={Column::Dependencies} expandable=true />
            <TableColumn<Column> label="Supplier" index={Column::Supplier} />
            <TableColumn<Column> label="Created on" index={Column::Created} />
        </TableHeader<Column>>
    };

    let pagination = use_pagination(Some(total), || PaginationControl { page: 1, per_page: 10 });

    html!(
        <div class="pf-v5-u-background-color-100">
            <PaginationWrapped pagination={pagination} total={10}>
                <Table<Column, UseTableData<Column, MemoizedTableModel<TableData>>>
                    mode={TableMode::Expandable}
                    {header}
                    {entries}
                    {onexpand}
                />
            </PaginationWrapped>
        </div>
    )
}
