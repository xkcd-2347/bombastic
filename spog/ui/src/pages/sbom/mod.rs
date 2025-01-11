//! The SBOM details page

use crate::{common::clean_ext, model, pages::sbom_report::SbomReport};
use patternfly_yew::prelude::*;
use reqwest::Body;
use spog_ui_backend::{use_backend, AnalyzeService};
use spog_ui_common::error::components::ApiError;
use spog_ui_common::{config::use_config_private, error::components::Error};
use spog_ui_components::download::{SbomKebabDropdown, SbomSource};
use spog_ui_components::{
    common::{NotFound, PageHeading},
    content::{SourceCode, Technical},
    cyclonedx::*,
    sbom::Report,
    spdx::*,
};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_oauth2::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct SBOMProperties {
    pub id: String,
}

#[function_component(SBOM)]
pub fn sbom(props: &SBOMProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let info = use_async_with_cloned_deps(
        |(id, backend, access_token)| async move {
            spog_ui_backend::SBOMService::new(backend.clone(), access_token)
                .get(id)
                .await
                .map(|result| result.map(model::SBOM::parse).map(Rc::new))
        },
        (props.id.clone(), backend.clone(), access_token.clone()),
    );

    let sbom_index = use_async_with_cloned_deps(
        |(id, backend, access_token)| async move {
            spog_ui_backend::SBOMService::new(backend.clone(), access_token)
                .get_from_index(&id)
                .await
                .map(|search_result| {
                    if search_result.result.len() == 1 {
                        let data = &search_result.result[0];
                        Some(data.clone())
                    } else {
                        None
                    }
                })
        },
        (props.id.clone(), backend.clone(), access_token.clone()),
    );

    let title = match &*sbom_index {
        UseAsyncState::Ready(Ok(Some(data))) => html!(data.name.clone()),
        _ => html!(props.id.clone()),
    };

    let (heading, content) = match &*info {
        UseAsyncState::Pending | UseAsyncState::Processing => (
            html!(<PageHeading>{title}</PageHeading>),
            html!(<PageSection fill={PageSectionFill::Fill}><Spinner/></PageSection>),
        ),
        UseAsyncState::Ready(Ok(None)) => (
            html!(<PageHeading sticky=false>{title} {" "} </PageHeading>),
            html!(<NotFound/>),
        ),
        UseAsyncState::Ready(Ok(Some(data))) => {
            let download_button = match &*sbom_index {
                UseAsyncState::Ready(Ok(Some(data_index))) => {
                    let filename = format!("{}.json", data_index.name);
                    html!(<SbomKebabDropdown id={props.id.clone()} sbom_source={SbomSource::LOCAL(data.get_source(), filename)} dropdown_text={"Download"} />)
                }
                _ => {
                    html!(<SbomKebabDropdown id={props.id.clone()} sbom_source={SbomSource::LOCAL(data.get_source(), clean_ext(&props.id))} dropdown_text={"Download"} />)
                }
            };

            (
                html!(
                    <PageSection variant={PageSectionVariant::Light} >
                        <Split gutter=true>
                            <SplitItem fill=true>
                                <Content>
                                    <Title>
                                        {title} {" "} <Label label={data.type_name()} color={Color::Blue} />
                                    </Title>
                                    <p>
                                        {"To generate a report, SBOM content will be processed by Red Hat’s Dependency Analytics Service. The SBOM data will be deleted from the Dependency Analytics Service once the report has been generated. Contact"}
                                        {" "}<a href="mailto:rhtpa-support@redhat.com">{"rhtpa-support@redhat.com"}</a>{" "}
                                        {"if you have any questions or concerns."}
                                    </p>
                                </Content>
                            </SplitItem>
                            <SplitItem>
                                {download_button}
                            </SplitItem>
                        </Split>
                    </PageSection>
                ),
                html!(<Details id={props.id.clone()} sbom={data.clone()}/> ),
            )
        }
        UseAsyncState::Ready(Err(err)) => (
            html!(<PageHeading>{title}</PageHeading>),
            html!(<PageSection fill={PageSectionFill::Fill}><Error err={err.to_string()} /></PageSection>),
        ),
    };

    html!(
        <>
            { heading }
            { content }
        </>
    )
}

#[derive(Clone, PartialEq, Properties)]
struct DetailsProps {
    id: String,
    sbom: Rc<model::SBOM>,
}

#[function_component(Details)]
fn details(props: &DetailsProps) -> Html {
    #[derive(Copy, Clone, Eq, PartialEq)]
    enum TabIndex {
        Overview,
        Info,
        Packages,
        Source,
        Report,
    }

    let config = use_config_private();

    let tab = use_state_eq(|| TabIndex::Info);
    let onselect = use_callback(tab.clone(), |index, tab| tab.set(index));

    match &*props.sbom {
        model::SBOM::SPDX { bom, source } => {
            html!(
                <>
                    <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                        <Tabs<TabIndex> inset={TabInset::Page} detached=true selected={*tab} {onselect}>
                            <Tab<TabIndex> index={TabIndex::Info} title="Info" />
                            <Tab<TabIndex> index={TabIndex::Packages} title="Packages" />
                            <Tab<TabIndex> index={TabIndex::Overview} title={html!(
                                <>
                                    { "Vulnerabilities" }
                                    <Popover
                                        target={html!(
                                            <button class="pf-v5-c-button pf-m-plain pf-m-small" type="button" style="padding: 0px 0px 0px 5px;">
                                                <span class="pf-v5-c-tabs__item-action-icon">
                                                { Icon::QuestionCircle }
                                                </span>
                                            </button>
                                        )}
                                        body={html_nested!(
                                            <PopoverBody>{"Any found vulnerabilities related to this SBOM. Fixed vulnerabilities are not listed."}</PopoverBody>
                                        )}
                                    />
                                </>
                            )}/>
                            { for config.features.show_report.then(|| html_nested!(
                                <Tab<TabIndex> index={TabIndex::Report} title="Dependency Analytics Report" />
                            )) }
                            { for config.features.show_source.then(|| html_nested!(
                                <Tab<TabIndex> index={TabIndex::Source} title="Source" />
                            )) }
                        </Tabs<TabIndex>>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Overview} fill={PageSectionFill::Fill}>
                        <SbomReport id={props.id.clone()} />
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Info} fill={PageSectionFill::Fill}>
                        <Stack gutter=true>
                            <StackItem>
                                <Grid gutter=true>
                                    <GridItem cols={[6]}>{spdx_meta(bom)}</GridItem>
                                    <GridItem cols={[3]}>{spdx_creator(bom)}</GridItem>
                                    <GridItem cols={[3]}>{spdx_stats(source.as_bytes().len(), bom)}</GridItem>
                                </Grid>
                            </StackItem>
                            <StackItem>
                                <Grid gutter=true>
                                    <GridItem cols={[12]}>{spdx_main(bom)}</GridItem>
                                </Grid>
                            </StackItem>
                        </Stack>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Packages} fill={PageSectionFill::Fill}>
                        <SpdxPackages bom={bom.clone()} />
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Source} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                        <SourceCode source={source.clone()} />
                    </PageSection>
                    <PageSection hidden={*tab != TabIndex::Report} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                        <ReportViewwer raw={source.clone()}/>
                    </PageSection>
                </>
            )
        }
        model::SBOM::CycloneDX { bom, source } => {
            html!(
                <>
                    <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                        <Tabs<TabIndex> inset={TabInset::Page} detached=true selected={*tab} {onselect}>
                            <Tab<TabIndex> index={TabIndex::Info} title="Info" />
                            <Tab<TabIndex> index={TabIndex::Packages} title="Packages" />
                            <Tab<TabIndex> index={TabIndex::Overview} title={html!(
                                <>
                                    { "Vulnerabilities" }
                                    <Popover
                                        target={html!(
                                            <button class="pf-v5-c-button pf-m-plain pf-m-small" type="button" style="padding: 0px 0px 0px 5px;">
                                                <span class="pf-v5-c-tabs__item-action-icon">
                                                { Icon::QuestionCircle }
                                                </span>
                                            </button>
                                        )}
                                        body={html_nested!(
                                            <PopoverBody>{"Any found vulnerabilities related to this SBOM. Fixed vulnerabilities are not listed."}</PopoverBody>
                                        )}
                                    />
                                </>
                            )}/>
                            // { for config.features.show_report.then(|| html_nested!(
                            //     <Tab<TabIndex> index={TabIndex::Report} title="Dependency Analytics Report" />
                            // )) }
                            { for config.features.show_source.then(|| html_nested!(
                                <Tab<TabIndex> index={TabIndex::Source} title="Source" />
                            )) }
                        </Tabs<TabIndex>>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Overview} fill={PageSectionFill::Fill}>
                        <SbomReport id={props.id.clone()} />
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Info} fill={PageSectionFill::Fill}>
                        <Stack gutter=true>
                            <StackItem>
                                <Grid gutter=true>
                                    <GridItem cols={[6]}><CycloneDXMeta bom={bom.clone()} source={source.clone()}/></GridItem>
                                    <GridItem cols={[3]}>{cyclonedx_creator(bom)}</GridItem>
                                    <GridItem cols={[3]}>
                                        <GridItem cols={[2]}><Technical size={source.as_bytes().len()}/></GridItem>
                                    </GridItem>
                                </Grid>
                            </StackItem>
                            <StackItem>
                                <Grid gutter=true>
                                    <GridItem cols={[12]}>{cyclonedx_main(bom)}</GridItem>
                                </Grid>
                            </StackItem>
                        </Stack>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Packages} fill={PageSectionFill::Fill}>
                        <CycloneDxPackages bom={bom.clone()} />
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Source} fill={PageSectionFill::Fill}>
                        <SourceCode source={source.clone()} />
                    </PageSection>
                    <PageSection hidden={*tab != TabIndex::Report} fill={PageSectionFill::Fill}>
                        <ReportViewwer raw={source.clone()}/>
                    </PageSection>
                </>
            )
        }
        model::SBOM::Unknown(source) => {
            html!(
                <>
                    <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                        <Tabs<TabIndex> inset={TabInset::Page} detached=true selected={*tab} {onselect}>
                            <Tab<TabIndex> index={TabIndex::Overview} title="Overview" />
                            <Tab<TabIndex> index={TabIndex::Info} title="Info" />
                            <Tab<TabIndex> index={TabIndex::Source} title="Source" />
                        </Tabs<TabIndex>>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Overview} fill={PageSectionFill::Fill}>
                        <SbomReport id={props.id.clone()} />
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Info} fill={PageSectionFill::Fill}>
                        <Grid gutter=true>
                            <GridItem cols={[2]}><Technical size={source.as_bytes().len()}/></GridItem>
                        </Grid>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Source} fill={PageSectionFill::Fill}>
                        <SourceCode source={source.clone()} />
                    </PageSection>
                    <PageSection hidden={*tab != TabIndex::Report} fill={PageSectionFill::Fill}>
                        <ReportViewwer raw={source.clone()}/>
                    </PageSection>
                </>
            )
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct ReportViewwerProperties {
    pub raw: Rc<String>,
}

#[function_component(ReportViewwer)]
pub fn report_viewer(props: &ReportViewwerProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let fetch = {
        use_async_with_cloned_deps(
            move |raw| async move {
                let service = AnalyzeService::new(backend, access_token);
                service.report(Body::from((*raw).clone())).await.map(Rc::new)
            },
            props.raw.clone(),
        )
    };

    html!(
        <>
            {
                match &*fetch {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(Ok(data)) => html!(
                        <Report data={data.clone()} />
                    ),
                    UseAsyncState::Ready(Err(err)) => html!(
                        <ApiError error={err.clone()} />
                    )
                }
            }
        </>
    )
}
