use crate::backend::{SearchOptions, VexService};
use crate::hooks::use_backend;
use csaf::Csaf;
use details::CsafDetails;
use patternfly_yew::{
    next::{
        use_table_data, Cell, CellContext, ColumnWidth, MemoizedTableModel, Table, TableColumn, TableEntryRenderer,
        TableHeader, UseTableData,
    },
    prelude::*,
};
use patternfly_yew::{
    next::{Toolbar, ToolbarContent},
    prelude::*,
};
use spog_model::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps};

#[derive(PartialEq, Properties)]
pub struct AdvisorySearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<Csaf>>>, String>>,

    pub id: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,
}

#[function_component(AdvisorySearch)]
pub fn advisory_search(props: &AdvisorySearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| VexService::new((**backend).clone()), backend.clone());

    let offset = use_state_eq(|| 0);
    let limit = use_state_eq(|| 10);

    // the active query
    let state = use_state_eq(|| {
        // initialize with the state from history, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| state.as_string())
            .unwrap_or_else(|| props.id.clone().unwrap_or_else(String::default))
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(state, offset, limit)| async move {
                service
                    .search_advisories(
                        &state,
                        &SearchOptions {
                            offset: Some(offset),
                            limit: Some(limit),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*state).clone(), *offset, *limit),
        )
    };

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (props.callback.clone(), search.clone()),
    );

    // the current value in the text input field
    let text = use_state_eq(|| (*state).clone());

    let onclear = {
        let text = text.clone();
        Callback::from(move |_| {
            text.set(String::new());
        })
    };
    let onset = {
        let state = state.clone();
        let text = text.clone();
        Callback::from(move |()| {
            state.set((*text).clone());
        })
    };

    use_effect_with_deps(
        |query| {
            // store changes to the state in the current history
            let _ = gloo_utils::history().replace_state(&query.into(), "");
        },
        (*state).clone(),
    );

    // pagination

    let total = search.data().and_then(|d| d.total);
    let onlimit = {
        let limit = limit.clone();
        Callback::from(move |n| {
            limit.set(n);
        })
    };
    let onnavigation = {
        if let Some(total) = total {
            let offset = offset.clone();

            let limit = limit.clone();
            Callback::from(move |nav| {
                let o = match nav {
                    Navigation::First => 0,
                    Navigation::Last => total - *limit,
                    Navigation::Next => *offset + *limit,
                    Navigation::Previous => *offset - *limit,
                    Navigation::Page(n) => *limit * n - 1,
                };
                offset.set(o);
            })
        } else {
            Callback::default()
        }
    };

    // render

    html!(
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarGroup>
                        <ToolbarItem r#type={ToolbarItemType::SearchFilter} width={["600px".to_string()]}>
                            <Form onsubmit={onset.reform(|_|())}>
                                // needed to trigger submit when pressing enter in the search field
                                <input type="submit" hidden=true formmethod="dialog" />
                                <InputGroup>
                                    <TextInputGroup>
                                        <TextInputGroupMain
                                            icon={Icon::Search}
                                            placeholder="Search"
                                            value={(*text).clone()}
                                            oninput={ Callback::from(move |data| text.set(data)) }
                                        />
                                        <TextInputGroupUtilities>
                                            <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclear} />
                                        </TextInputGroupUtilities>
                                        <Button icon={Icon::ArrowRight} variant={ButtonVariant::Control} onclick={onset.reform(|_|())} />
                                    </TextInputGroup>
                                </InputGroup>
                            </Form>
                        </ToolbarItem>
                    </ToolbarGroup>

                    { for props.toolbar_items.iter() }

                    <ToolbarItem r#type={ToolbarItemType::Pagination}>
                        <Pagination
                            total_entries={total}
                            selected_choice={*limit}
                            offset={*offset}
                            entries_per_page_choices={vec![10, 25, 50]}
                            {onnavigation}
                            {onlimit}
                        >
                        </Pagination>
                    </ToolbarItem>

                </ToolbarContent>
                // <ToolbarContent> { for filters.into_iter() } </ToolbarContent>
            </Toolbar>

        </>
    )
}

#[derive(Debug, Properties)]
pub struct AdvisoryResultProperties {
    pub result: SearchResult<Rc<Vec<csaf::Csaf>>>,
}

impl PartialEq for AdvisoryResultProperties {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.result, &other.result)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Title,
    Revision,
    Products,
    Download,
    Vulnerabilities,
}

impl TableEntryRenderer<Column> for Csaf {
    fn render_cell(&self, context: &CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(&self.document.tracking.id).into(),
            Column::Title => html!(&self.document.title).into(),
            Column::Revision => html!(&self.document.tracking.current_release_date.to_rfc3339()).into(),
            Column::Products => html!().into(),
            Column::Download => html!(<a href={format!("/api/v1/advisory?id={}", self.document.tracking.id)}>{"Download"}</a>).into(),
            Column::Vulnerabilities => self
                .vulnerabilities
                .as_ref()
                .map(|v| html!(v.len().to_string()))
                .unwrap_or_else(|| html!(<i>{"N/A"}</i>))
                .into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(<CsafDetails csaf={Rc::new(self.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(AdvisoryResult)]
pub fn vulnerability_result(props: &AdvisoryResultProperties) -> Html {
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(props.result.result.clone()));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="ID" index={Column::Id} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Title" index={Column::Title} width={ColumnWidth::Percent(45)}/>
            <TableColumn<Column> label="Revision" index={Column::Revision} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Products" index={Column::Products} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Download" index={Column::Products} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Vulnerabilities" index={Column::Vulnerabilities} width={ColumnWidth::Percent(10)}/>
        </TableHeader<Column>>
    };

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<Csaf>>>
            mode={TableMode::CompactExpandable}
            {header}
            {entries}
            {onexpand}
        />
    )
}

mod details {

    use crate::{components::cvss::CvssScore, utils::cvss::Cvss};
    use csaf::definitions::Branch;
    use csaf::product_tree::ProductTree;
    use csaf::{vulnerability::Vulnerability, Csaf};
    use patternfly_yew::{
        next::{use_table_data, MemoizedTableModel, Table, TableColumn, TableEntryRenderer, TableHeader, UseTableData},
        prelude::*,
    };
    use std::rc::Rc;
    use yew::prelude::*;

    #[derive(Clone, Properties)]
    pub struct CsafDetailsProps {
        pub csaf: Rc<Csaf>,
    }

    impl PartialEq for CsafDetailsProps {
        fn eq(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.csaf, &other.csaf)
        }
    }

    #[function_component(CsafDetails)]
    pub fn csaf_details(props: &CsafDetailsProps) -> Html {
        let vulns = use_memo(
            |props| props.csaf.vulnerabilities.clone().unwrap_or_default(),
            props.clone(),
        );

        let product = use_memo(
            |props| {
                props.csaf.product_tree.clone().unwrap_or_else(|| ProductTree {
                    branches: None,
                    product_groups: None,
                    full_product_names: None,
                    relationships: None,
                })
            },
            props.clone(),
        );

        html!(
            <Grid gutter=true>
                <GridItem cols={[6.all()]}>
                    <CsafVulnTable entries={vulns}/>
                </GridItem>
                <GridItem cols={[6.all()]}>
                    <CsafProductInfo {product}/>
                </GridItem>
            </Grid>
        )
    }

    // vulns

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Column {
        Cve,
        Title,
        Cwe,
        Score,
    }

    #[derive(Properties)]
    pub struct CsafVulnTableProperties {
        pub entries: Rc<Vec<Vulnerability>>,
    }

    impl PartialEq for CsafVulnTableProperties {
        fn eq(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.entries, &other.entries)
        }
    }

    impl TableEntryRenderer<Column> for Vulnerability {
        fn render_cell(&self, context: &patternfly_yew::next::CellContext<'_, Column>) -> patternfly_yew::next::Cell {
            match context.column {
                Column::Cve => self
                    .cve
                    .clone()
                    .map(|cve| html!(cve))
                    .unwrap_or_else(|| html!(<i>{"N/A"}</i>)),
                Column::Title => self.title.clone().map(Html::from).unwrap_or_default(),
                Column::Score => self
                    .scores
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|s| s.cvss_v3)
                    .map(|s| Cvss {
                        score: s.score().value() as f32,
                        status: String::new(),
                    })
                    .map(|cvss| html!(<CvssScore {cvss}/>))
                    .collect::<Html>(),
                Column::Cwe => self
                    .cwe
                    .clone()
                    .map(|cwe| {
                        html!(<Tooltip text={cwe.name}>
                        {cwe.id}
                    </Tooltip>)
                    })
                    .unwrap_or_else(|| html!(<i>{"N/A"}</i>)),
            }
            .into()
        }
    }

    #[function_component(CsafVulnTable)]
    pub fn vulnerability_table(props: &CsafVulnTableProperties) -> Html {
        let (entries, onexpand) = use_table_data(MemoizedTableModel::new(props.entries.clone()));

        let header = html_nested! {
            <TableHeader<Column>>
                <TableColumn<Column> label="CVE ID" index={Column::Cve} />
                <TableColumn<Column> label="Title" index={Column::Title} />
                <TableColumn<Column> label="Score" index={Column::Score} />
                <TableColumn<Column> label="CWE" index={Column::Cwe} />
            </TableHeader<Column>>
        };

        html!(
            <Table<Column, UseTableData<Column, MemoizedTableModel<Vulnerability>>>
                mode={TableMode::Compact}
                {header}
                {entries}
                {onexpand}
            />
        )
    }

    // products

    #[derive(Properties)]
    pub struct CsafProductInfoProperties {
        pub product: Rc<ProductTree>,
    }

    impl PartialEq for CsafProductInfoProperties {
        fn eq(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.product, &other.product)
        }
    }

    struct ProductTreeWrapper(Rc<ProductTree>);

    impl PartialEq for ProductTreeWrapper {
        fn eq(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.0, &other.0)
        }
    }

    struct BranchWrapper(Branch);

    impl TreeTableModel for ProductTreeWrapper {
        fn children(&self) -> Vec<Rc<dyn TreeNode>> {
            self.0
                .branches
                .iter()
                .flat_map(|s| s.0.iter())
                .map(|branch| Rc::new(BranchWrapper(branch.clone())) as Rc<dyn TreeNode>)
                .collect()
        }
    }

    impl TreeNode for BranchWrapper {
        fn render_main(&self) -> Cell {
            html!(<>
            { &self.0.name } { " " }
            <Label color={Color::Blue} label={format!("{:?}", self.0.category)} outline=true compact=true/>
        </>)
            .into()
        }

        fn render_cell(&self, ctx: CellContext) -> Cell {
            match ctx.column {
                _ => html!(),
            }
            .into()
        }

        fn children(&self) -> Vec<Rc<dyn TreeNode>> {
            self.0
                .branches
                .iter()
                .flat_map(|s| s.0.iter())
                .map(|branch| Rc::new(BranchWrapper(branch.clone())) as Rc<dyn TreeNode>)
                .collect()
        }
    }

    #[function_component(CsafProductInfo)]
    pub fn product_info(props: &CsafProductInfoProperties) -> Html {
        use patternfly_yew::prelude::TableColumn;

        let header = html_nested! {
            <TreeTableHeader>
                <TableColumn label="Name"/>
            </TreeTableHeader>
        };

        let root = Rc::new(ProductTreeWrapper(props.product.clone()));

        html!(
            <TreeTable<ProductTreeWrapper>
                mode={TreeTableMode::Compact}
                header={header}
                model={root}
            />
        )
    }
}
